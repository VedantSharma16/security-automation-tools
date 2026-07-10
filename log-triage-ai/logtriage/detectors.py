"""Rule-based detection engine, mapped to MITRE ATT&CK techniques.

Each detector takes a chronologically-ordered list of `LogEvent`s and
returns zero or more `Alert`s. Detectors are independent and composable —
`TriageEngine` runs the default set, but each can be used standalone.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta

from .models import Alert, EventType, LogEvent

# Commands commonly used for privilege escalation or persistence once an
# attacker has sudo access.
_SUSPICIOUS_SUDO_PATTERNS = [
    (re.compile(r"chmod\s+([4-7])[0-7]{3}\s+.*(bash|sh)\b"), "SUID bit set on a shell binary"),
    (re.compile(r"/etc/shadow"), "Direct access to /etc/shadow"),
    (re.compile(r"/etc/sudoers"), "Direct edit of /etc/sudoers"),
    (re.compile(r"usermod\s+.*-a?G\s*sudo"), "User added to the sudo group"),
    (re.compile(r"nc\s+.*-e\s+/bin/(ba)?sh"), "Netcat reverse shell"),
    (re.compile(r"/dev/tcp/"), "Bash /dev/tcp reverse shell"),
    (re.compile(r"curl\s+.*\|\s*(ba)?sh"), "Piped remote script execution (curl | sh)"),
    (re.compile(r"wget\s+.*\|\s*(ba)?sh"), "Piped remote script execution (wget | sh)"),
]


class BruteForceDetector:
    """Flags a source IP with >= threshold failed logins within a time window."""

    def __init__(self, threshold: int = 5, window: timedelta = timedelta(seconds=60)):
        self.threshold = threshold
        self.window = window

    def detect(self, events: list[LogEvent]) -> list[Alert]:
        failures_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for event in events:
            if event.event_type == EventType.AUTH_FAILURE and event.source_ip:
                failures_by_ip[event.source_ip].append(event)

        alerts = []
        for ip, failures in failures_by_ip.items():
            failures.sort(key=lambda e: e.timestamp)
            for i, start in enumerate(failures):
                window_events = [
                    f for f in failures[i:] if f.timestamp - start.timestamp <= self.window
                ]
                if len(window_events) >= self.threshold:
                    alerts.append(
                        Alert(
                            id=f"brute-force-{ip}",
                            type="brute_force",
                            severity="high",
                            title=f"Brute-force SSH login attempts from {ip}",
                            description=(
                                f"{len(window_events)} failed login attempts from {ip} "
                                f"within {int(self.window.total_seconds())}s."
                            ),
                            mitre_technique="T1110 - Brute Force",
                            source_ip=ip,
                            related_raw=[e.raw for e in window_events],
                            first_seen=window_events[0].timestamp,
                            last_seen=window_events[-1].timestamp,
                        )
                    )
                    break  # one alert per offending IP is enough
        return alerts


class CredentialCompromiseDetector:
    """Flags a successful login from an IP that recently failed repeatedly.

    A run of failed attempts followed by a success from the same IP is a
    strong signal that a brute-force or credential-stuffing attempt
    succeeded.
    """

    def __init__(self, min_prior_failures: int = 3, lookback: timedelta = timedelta(minutes=10)):
        self.min_prior_failures = min_prior_failures
        self.lookback = lookback

    def detect(self, events: list[LogEvent]) -> list[Alert]:
        ordered = sorted(events, key=lambda e: e.timestamp)
        failures_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        alerts = []

        for event in ordered:
            if event.event_type == EventType.AUTH_FAILURE and event.source_ip:
                failures_by_ip[event.source_ip].append(event)
                continue

            if event.event_type == EventType.AUTH_SUCCESS and event.source_ip:
                ip = event.source_ip
                recent_failures = [
                    f for f in failures_by_ip.get(ip, [])
                    if event.timestamp - f.timestamp <= self.lookback
                ]
                if len(recent_failures) >= self.min_prior_failures:
                    related = [f.raw for f in recent_failures] + [event.raw]
                    alerts.append(
                        Alert(
                            id=f"credential-compromise-{ip}",
                            type="credential_compromise",
                            severity="critical",
                            title=f"Successful login from {ip} after repeated failures",
                            description=(
                                f"User '{event.user}' logged in successfully from {ip} "
                                f"after {len(recent_failures)} failed attempts in the "
                                f"preceding {int(self.lookback.total_seconds() // 60)} minutes. "
                                "Likely credential compromise."
                            ),
                            mitre_technique="T1078 - Valid Accounts",
                            source_ip=ip,
                            related_raw=related,
                            first_seen=recent_failures[0].timestamp,
                            last_seen=event.timestamp,
                        )
                    )
        return alerts


class PrivilegeEscalationDetector:
    """Flags sudo commands matching known privilege-escalation patterns."""

    def detect(self, events: list[LogEvent]) -> list[Alert]:
        alerts = []
        for event in events:
            if event.event_type != EventType.SUDO_COMMAND or not event.command:
                continue
            for pattern, reason in _SUSPICIOUS_SUDO_PATTERNS:
                if pattern.search(event.command):
                    alerts.append(
                        Alert(
                            id=f"privesc-{event.user}-{event.timestamp.isoformat()}",
                            type="privilege_escalation",
                            severity="high",
                            title=f"Suspicious sudo command by {event.user}",
                            description=f"{reason}: `{event.command}`",
                            mitre_technique="T1548 - Abuse Elevation Control Mechanism",
                            source_ip=None,
                            related_raw=[event.raw],
                            first_seen=event.timestamp,
                            last_seen=event.timestamp,
                        )
                    )
                    break
        return alerts


DEFAULT_DETECTORS = [
    BruteForceDetector(),
    CredentialCompromiseDetector(),
    PrivilegeEscalationDetector(),
]


def run_detectors(events: list[LogEvent], detectors=None) -> list[Alert]:
    """Run each detector over the events and return the combined alert list."""
    detectors = detectors if detectors is not None else DEFAULT_DETECTORS
    alerts: list[Alert] = []
    for detector in detectors:
        alerts.extend(detector.detect(events))
    return alerts
