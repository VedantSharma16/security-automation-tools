"""Rule-based anomaly detection over parsed SSH auth log entries."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from .parser import EventType, LogEntry


class FindingType(str, Enum):
    BRUTE_FORCE = "BRUTE_FORCE"
    CREDENTIAL_COMPROMISE_SUSPECTED = "CREDENTIAL_COMPROMISE_SUSPECTED"
    USER_ENUMERATION = "USER_ENUMERATION"
    ANOMALOUS_LOGIN_TIME = "ANOMALOUS_LOGIN_TIME"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Loose mapping to MITRE ATT&CK for context in reports. Kept conservative:
# only technique IDs that clearly apply are cited.
_MITRE = {
    FindingType.BRUTE_FORCE: "T1110 (Brute Force)",
    FindingType.CREDENTIAL_COMPROMISE_SUSPECTED: "T1078 (Valid Accounts)",
    FindingType.USER_ENUMERATION: "TA0043 (Reconnaissance)",
    FindingType.ANOMALOUS_LOGIN_TIME: None,
}


@dataclass
class Finding:
    type: FindingType
    severity: Severity
    source_ip: str
    users: list[str]
    count: int
    first_seen: datetime
    last_seen: datetime
    description: str
    mitre_technique: Optional[str] = None
    evidence: list[str] = field(default_factory=list)


@dataclass
class DetectorConfig:
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 60
    enumeration_threshold: int = 3
    off_hours_start: int = 6  # inclusive, local log time
    off_hours_end: int = 22  # exclusive


def _sliding_window_hit(timestamps: list[datetime], threshold: int, window_seconds: int) -> bool:
    """True if `threshold` events occur within any `window_seconds` span."""
    if len(timestamps) < threshold:
        return False
    ts = sorted(timestamps)
    left = 0
    for right in range(len(ts)):
        while (ts[right] - ts[left]).total_seconds() > window_seconds:
            left += 1
        if right - left + 1 >= threshold:
            return True
    return False


def detect(entries: list[LogEntry], config: Optional[DetectorConfig] = None) -> list[Finding]:
    """Run all detection rules over a list of parsed log entries."""
    config = config or DetectorConfig()
    findings: list[Finding] = []

    by_ip: dict[str, list[LogEntry]] = defaultdict(list)
    for entry in entries:
        by_ip[entry.source_ip].append(entry)

    brute_forced_ips: set[str] = set()

    for ip, ip_entries in by_ip.items():
        ip_entries.sort(key=lambda e: e.timestamp)
        failed = [
            e
            for e in ip_entries
            if e.event in (EventType.FAILED_PASSWORD, EventType.FAILED_INVALID_USER)
        ]
        accepted = [e for e in ip_entries if e.event == EventType.ACCEPTED]
        invalid_users = [e for e in ip_entries if e.event == EventType.INVALID_USER]

        # Rule 1: brute force — threshold+ failed attempts within a sliding window.
        if _sliding_window_hit(
            [e.timestamp for e in failed],
            config.brute_force_threshold,
            config.brute_force_window_seconds,
        ):
            brute_forced_ips.add(ip)
            users = sorted({e.user for e in failed})
            severity = (
                Severity.CRITICAL if len(failed) >= 2 * config.brute_force_threshold else Severity.HIGH
            )
            findings.append(
                Finding(
                    type=FindingType.BRUTE_FORCE,
                    severity=severity,
                    source_ip=ip,
                    users=users,
                    count=len(failed),
                    first_seen=failed[0].timestamp,
                    last_seen=failed[-1].timestamp,
                    description=(
                        f"{len(failed)} failed SSH authentication attempts from {ip} "
                        f"targeting {len(users)} account(s) ({', '.join(users[:5])}"
                        f"{'...' if len(users) > 5 else ''}) within a "
                        f"{config.brute_force_window_seconds}s window."
                    ),
                    mitre_technique=_MITRE[FindingType.BRUTE_FORCE],
                    evidence=[e.raw for e in failed[:10]],
                )
            )

        # Rule 2: successful login from an IP that also failed at least once.
        if accepted and failed:
            severity = Severity.CRITICAL if ip in brute_forced_ips else Severity.MEDIUM
            users = sorted({e.user for e in accepted})
            findings.append(
                Finding(
                    type=FindingType.CREDENTIAL_COMPROMISE_SUSPECTED,
                    severity=severity,
                    source_ip=ip,
                    users=users,
                    count=len(accepted),
                    first_seen=accepted[0].timestamp,
                    last_seen=accepted[-1].timestamp,
                    description=(
                        f"{ip} had {len(failed)} failed attempt(s) followed by a successful "
                        f"login as {', '.join(users)}. Credentials may be compromised."
                    ),
                    mitre_technique=_MITRE[FindingType.CREDENTIAL_COMPROMISE_SUSPECTED],
                    evidence=[e.raw for e in accepted[:5]],
                )
            )

        # Rule 3: enumeration of nonexistent usernames.
        distinct_invalid_users = sorted({e.user for e in invalid_users})
        if len(distinct_invalid_users) >= config.enumeration_threshold:
            findings.append(
                Finding(
                    type=FindingType.USER_ENUMERATION,
                    severity=Severity.MEDIUM,
                    source_ip=ip,
                    users=distinct_invalid_users,
                    count=len(invalid_users),
                    first_seen=invalid_users[0].timestamp,
                    last_seen=invalid_users[-1].timestamp,
                    description=(
                        f"{ip} probed {len(distinct_invalid_users)} nonexistent usernames "
                        f"({', '.join(distinct_invalid_users[:5])}"
                        f"{'...' if len(distinct_invalid_users) > 5 else ''}), "
                        "consistent with account enumeration."
                    ),
                    mitre_technique=_MITRE[FindingType.USER_ENUMERATION],
                    evidence=[e.raw for e in invalid_users[:10]],
                )
            )

        # Rule 4: successful logins outside normal business hours.
        for e in accepted:
            hour = e.timestamp.hour
            if not (config.off_hours_start <= hour < config.off_hours_end):
                findings.append(
                    Finding(
                        type=FindingType.ANOMALOUS_LOGIN_TIME,
                        severity=Severity.LOW,
                        source_ip=ip,
                        users=[e.user],
                        count=1,
                        first_seen=e.timestamp,
                        last_seen=e.timestamp,
                        description=(
                            f"Successful login as {e.user} from {ip} at "
                            f"{e.timestamp.strftime('%H:%M:%S')}, outside the configured "
                            f"business-hours window "
                            f"({config.off_hours_start:02d}:00-{config.off_hours_end:02d}:00)."
                        ),
                        mitre_technique=_MITRE[FindingType.ANOMALOUS_LOGIN_TIME],
                        evidence=[e.raw],
                    )
                )

    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.first_seen), reverse=True)
    return findings


_SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}
