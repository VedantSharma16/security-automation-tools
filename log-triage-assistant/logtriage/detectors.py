"""Rule-based detectors that turn parsed Events into security findings.

Each detector looks for one pattern commonly triaged during incident response:

  - BruteForceDetector: many failed SSH logins from one IP in a short window.
  - CompromiseAfterBruteForceDetector: a successful login from an IP that had
    just been failing password attempts (a classic sign of a cracked password).
  - PrivilegeEscalationDetector: sudo usage that elevates to root, escalated to
    CRITICAL if it happens shortly after a suspected compromise.
  - PersistenceDetector: root-equivalent (UID 0) account creation, and crontab
    edits, both common attacker persistence mechanisms.

Detectors are independent and composable: `run_all_detectors` runs them in a
fixed order so later detectors (privilege escalation, persistence) can use the
brute-force/compromise findings already produced for temporal correlation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from .parser import Event
from .scoring import Severity

DEFAULT_BRUTE_FORCE_WINDOW_SECONDS = 60
DEFAULT_BRUTE_FORCE_THRESHOLD = 5
COMPROMISE_LOOKBACK_SECONDS = 120
COMPROMISE_MIN_FAILURES = 3
ESCALATION_CORRELATION_SECONDS = 600


@dataclass
class Finding:
    type: str
    severity: Severity
    title: str
    description: str
    evidence: dict
    first_seen: datetime
    last_seen: datetime

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


def detect_brute_force(
    events: list[Event],
    window_seconds: int = DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,
    threshold: int = DEFAULT_BRUTE_FORCE_THRESHOLD,
) -> list[Finding]:
    """Flag source IPs with >= threshold failed SSH logins inside a sliding window."""
    failures_by_ip: dict[str, list[Event]] = {}
    for e in events:
        if e.kind == "ssh_failed_password":
            failures_by_ip.setdefault(e.fields["ip"], []).append(e)

    findings: list[Finding] = []
    window = timedelta(seconds=window_seconds)

    for ip, attempts in failures_by_ip.items():
        attempts.sort(key=lambda e: e.timestamp)
        start = 0
        for end in range(len(attempts)):
            while attempts[end].timestamp - attempts[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                cluster = attempts[start : end + 1]
                users = sorted({a.fields["user"] for a in cluster})
                findings.append(
                    Finding(
                        type="brute_force",
                        severity=Severity.HIGH,
                        title=f"Possible SSH brute force from {ip}",
                        description=(
                            f"{count} failed password attempts from {ip} within "
                            f"{window_seconds}s, targeting user(s): {', '.join(users)}."
                        ),
                        evidence={
                            "ip": ip,
                            "attempt_count": count,
                            "users_targeted": users,
                            "window_seconds": window_seconds,
                        },
                        first_seen=cluster[0].timestamp,
                        last_seen=cluster[-1].timestamp,
                    )
                )
                break  # one finding per IP is enough; avoid duplicate overlapping clusters
    return findings


def detect_compromise_after_brute_force(
    events: list[Event],
    lookback_seconds: int = COMPROMISE_LOOKBACK_SECONDS,
    min_prior_failures: int = COMPROMISE_MIN_FAILURES,
) -> list[Finding]:
    """Flag successful logins immediately preceded by multiple failures from the same IP."""
    findings: list[Finding] = []
    lookback = timedelta(seconds=lookback_seconds)

    accepted = [e for e in events if e.kind == "ssh_accepted"]
    failed = [e for e in events if e.kind == "ssh_failed_password"]

    for acc in accepted:
        prior_failures = [
            f
            for f in failed
            if f.fields["ip"] == acc.fields["ip"]
            and timedelta(0) <= acc.timestamp - f.timestamp <= lookback
        ]
        if len(prior_failures) >= min_prior_failures:
            findings.append(
                Finding(
                    type="compromise_after_brute_force",
                    severity=Severity.CRITICAL,
                    title=f"Successful login for '{acc.fields['user']}' after brute force",
                    description=(
                        f"{acc.fields['ip']} succeeded logging in as '{acc.fields['user']}' "
                        f"after {len(prior_failures)} failed attempts in the preceding "
                        f"{lookback_seconds}s. Credentials may be compromised."
                    ),
                    evidence={
                        "ip": acc.fields["ip"],
                        "user": acc.fields["user"],
                        "prior_failed_attempts": len(prior_failures),
                    },
                    first_seen=prior_failures[0].timestamp,
                    last_seen=acc.timestamp,
                )
            )
    return findings


def _near_prior_finding(timestamp: datetime, prior_findings: list[Finding], seconds: int) -> bool:
    window = timedelta(seconds=seconds)
    return any(
        timedelta(0) <= timestamp - pf.last_seen <= window for pf in prior_findings
    )


def detect_privilege_escalation(
    events: list[Event],
    prior_findings: Optional[list[Finding]] = None,
) -> list[Finding]:
    """Flag sudo usage that elevates to root; escalate severity if it follows a compromise."""
    prior_findings = prior_findings or []
    compromises = [f for f in prior_findings if f.type == "compromise_after_brute_force"]

    findings: list[Finding] = []
    for e in events:
        if e.kind != "sudo_command" or e.fields.get("target_user") != "root":
            continue

        correlated = _near_prior_finding(e.timestamp, compromises, ESCALATION_CORRELATION_SECONDS)
        severity = Severity.CRITICAL if correlated else Severity.MEDIUM
        description = (
            f"'{e.fields['invoker']}' ran '{e.fields['command']}' as root via sudo."
        )
        if correlated:
            description += " This occurred shortly after a suspected credential compromise."

        findings.append(
            Finding(
                type="privilege_escalation",
                severity=severity,
                title=f"Root privilege escalation by '{e.fields['invoker']}'",
                description=description,
                evidence={
                    "invoker": e.fields["invoker"],
                    "command": e.fields["command"],
                    "correlated_with_compromise": correlated,
                },
                first_seen=e.timestamp,
                last_seen=e.timestamp,
            )
        )
    return findings


def detect_persistence(events: list[Event]) -> list[Finding]:
    """Flag root-equivalent account creation and crontab edits (common persistence)."""
    findings: list[Finding] = []

    for e in events:
        if e.kind == "useradd" and e.fields.get("uid") == 0:
            findings.append(
                Finding(
                    type="persistence_root_account",
                    severity=Severity.CRITICAL,
                    title=f"Root-equivalent account created: {e.fields['name']}",
                    description=(
                        f"User '{e.fields['name']}' was created with UID=0 (root-equivalent), "
                        "a common backdoor persistence technique."
                    ),
                    evidence={"name": e.fields["name"], "uid": e.fields["uid"]},
                    first_seen=e.timestamp,
                    last_seen=e.timestamp,
                )
            )
        elif e.kind == "crontab_replace" and e.fields.get("action") == "REPLACE":
            findings.append(
                Finding(
                    type="persistence_crontab",
                    severity=Severity.MEDIUM,
                    title=f"Crontab replaced for user '{e.fields['user']}'",
                    description=(
                        f"The crontab for '{e.fields['user']}' was replaced, which can be "
                        "used to establish scheduled-task persistence."
                    ),
                    evidence={"user": e.fields["user"]},
                    first_seen=e.timestamp,
                    last_seen=e.timestamp,
                )
            )
    return findings


def run_all_detectors(events: list[Event], **kwargs) -> list[Finding]:
    """Run every detector in a fixed order, correlating later detectors with earlier findings."""
    findings: list[Finding] = []
    findings += detect_brute_force(
        events,
        window_seconds=kwargs.get("window_seconds", DEFAULT_BRUTE_FORCE_WINDOW_SECONDS),
        threshold=kwargs.get("threshold", DEFAULT_BRUTE_FORCE_THRESHOLD),
    )
    findings += detect_compromise_after_brute_force(events)
    findings += detect_privilege_escalation(events, prior_findings=findings)
    findings += detect_persistence(events)

    findings.sort(key=lambda f: f.first_seen)
    return findings
