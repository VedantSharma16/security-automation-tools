"""Rule-based detectors that turn a stream of auth Events into MITRE ATT&CK-tagged Findings.

Each detector is a plain function of (events, config) -> list[Finding] so they can be
unit tested in isolation and composed by TriageAgent / run_all_detectors.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from log_triage_agent.models import Event, EventType, Finding, Severity

# Risky sudo command fragments worth flagging as potential privilege escalation.
_RISKY_SUDO_COMMANDS = (
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "passwd",
    "visudo",
    "useradd",
    "usermod",
    "chmod",
    "su ",
)


@dataclass
class DetectorConfig:
    brute_force_window_minutes: int = 10
    brute_force_threshold: int = 5
    invalid_user_threshold: int = 3


def _within_window(times: list, window_minutes: int, threshold: int):
    """Return (window_start, window_end, count) for the densest cluster of timestamps
    that meets `threshold` within `window_minutes`, or None if no cluster qualifies.
    `times` must be sorted ascending.
    """
    from datetime import timedelta

    window = timedelta(minutes=window_minutes)
    best = None
    left = 0
    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        count = right - left + 1
        if count >= threshold and (best is None or count > best[2]):
            best = (times[left], times[right], count)
    return best


def detect_brute_force(events: list[Event], config: DetectorConfig) -> list[Finding]:
    """Flag source IPs with a cluster of auth failures exceeding threshold within the window."""
    by_ip: dict[str, list] = defaultdict(list)
    for e in events:
        if e.event_type in (EventType.AUTH_FAILURE, EventType.INVALID_USER) and e.source_ip:
            by_ip[e.source_ip].append(e.timestamp)

    findings = []
    for ip, timestamps in by_ip.items():
        timestamps.sort()
        cluster = _within_window(timestamps, config.brute_force_window_minutes, config.brute_force_threshold)
        if cluster:
            start, end, count = cluster
            findings.append(
                Finding(
                    title=f"SSH brute-force activity from {ip}",
                    severity=Severity.HIGH,
                    technique_id="T1110",
                    technique_name="Brute Force",
                    description=(
                        f"{count} failed authentication attempts from {ip} within "
                        f"{config.brute_force_window_minutes} minute(s)."
                    ),
                    source_ip=ip,
                    event_count=count,
                    first_seen=start,
                    last_seen=end,
                )
            )
    return findings


def detect_invalid_user_enumeration(events: list[Event], config: DetectorConfig) -> list[Finding]:
    """Flag source IPs probing multiple distinct usernames that don't exist on the system."""
    by_ip: dict[str, set] = defaultdict(set)
    times_by_ip: dict[str, list] = defaultdict(list)
    for e in events:
        if e.event_type == EventType.INVALID_USER and e.source_ip and e.username:
            by_ip[e.source_ip].add(e.username)
            times_by_ip[e.source_ip].append(e.timestamp)

    findings = []
    for ip, usernames in by_ip.items():
        if len(usernames) >= config.invalid_user_threshold:
            times = sorted(times_by_ip[ip])
            findings.append(
                Finding(
                    title=f"Username enumeration from {ip}",
                    severity=Severity.MEDIUM,
                    technique_id="T1087",
                    technique_name="Account Discovery",
                    description=(
                        f"{len(usernames)} distinct nonexistent usernames "
                        f"({', '.join(sorted(usernames))}) attempted from {ip}."
                    ),
                    source_ip=ip,
                    event_count=len(usernames),
                    first_seen=times[0],
                    last_seen=times[-1],
                )
            )
    return findings


def detect_successful_login_after_brute_force(
    events: list[Event], brute_force_findings: list[Finding]
) -> list[Finding]:
    """Flag a successful login from an IP that was previously flagged for brute-forcing —
    a strong signal of a compromised credential rather than a failed attack.
    """
    flagged_ips = {f.source_ip: f for f in brute_force_findings if f.source_ip}
    findings = []
    for e in events:
        if e.event_type == EventType.AUTH_SUCCESS and e.source_ip in flagged_ips:
            bf = flagged_ips[e.source_ip]
            if bf.last_seen and e.timestamp >= bf.first_seen:
                findings.append(
                    Finding(
                        title=f"Possible compromised credentials: {e.username}@{e.source_ip}",
                        severity=Severity.CRITICAL,
                        technique_id="T1078",
                        technique_name="Valid Accounts",
                        description=(
                            f"Successful login as '{e.username}' from {e.source_ip} after that IP "
                            f"was flagged for brute-force activity — the account may be compromised."
                        ),
                        source_ip=e.source_ip,
                        username=e.username,
                        event_count=1,
                        first_seen=e.timestamp,
                        last_seen=e.timestamp,
                    )
                )
    return findings


def detect_sudo_privilege_escalation(events: list[Event]) -> list[Finding]:
    """Flag sudo invocations that grant a full interactive shell or modify accounts/permissions."""
    findings = []
    for e in events:
        if e.event_type != EventType.SUDO_COMMAND:
            continue
        command = e.extra.get("command", "")
        if any(risky in command for risky in _RISKY_SUDO_COMMANDS):
            findings.append(
                Finding(
                    title=f"Sensitive sudo command by {e.username}",
                    severity=Severity.MEDIUM,
                    technique_id="T1548.003",
                    technique_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                    description=(
                        f"User '{e.username}' ran '{command}' as {e.extra.get('target_user')} via sudo."
                    ),
                    username=e.username,
                    event_count=1,
                    first_seen=e.timestamp,
                    last_seen=e.timestamp,
                )
            )
    return findings


def run_all_detectors(events: list[Event], config: DetectorConfig | None = None) -> list[Finding]:
    """Run every detector over the event stream and return a combined, chronologically-ordered
    list of findings, most severe first.
    """
    config = config or DetectorConfig()
    ordered_events = sorted(events, key=lambda e: e.timestamp)

    brute_force = detect_brute_force(ordered_events, config)
    findings = [
        *brute_force,
        *detect_invalid_user_enumeration(ordered_events, config),
        *detect_successful_login_after_brute_force(ordered_events, brute_force),
        *detect_sudo_privilege_escalation(ordered_events),
    ]
    return sorted(findings, key=lambda f: f.severity.rank, reverse=True)
