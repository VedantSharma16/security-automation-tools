"""Rule-based detectors that turn LogEvents into Alerts."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .models import Alert, LogEvent, Severity


class BruteForceDetector:
    """Flags a burst of failed password attempts from a single source IP."""

    rule_id = "SSH-001"

    def __init__(self, threshold: int = 5, window: timedelta = timedelta(minutes=5)):
        self.threshold = threshold
        self.window = window

    def run(self, events: list[LogEvent]) -> list[Alert]:
        failed = sorted(
            (e for e in events if e.action == "failed_password"),
            key=lambda e: e.timestamp,
        )
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for event in failed:
            by_ip[event.source_ip].append(event)

        alerts: list[Alert] = []
        for ip, ip_events in by_ip.items():
            window_start = 0
            for i, event in enumerate(ip_events):
                while event.timestamp - ip_events[window_start].timestamp > self.window:
                    window_start += 1
                window_events = ip_events[window_start : i + 1]
                if len(window_events) >= self.threshold:
                    alerts.append(
                        Alert(
                            rule_id=self.rule_id,
                            title="SSH brute-force attempt",
                            severity=Severity.HIGH,
                            description=(
                                f"{len(window_events)} failed password attempts from {ip} "
                                f"within {int(self.window.total_seconds() // 60)} minutes."
                            ),
                            events=list(window_events),
                            tags=["brute-force", "password", "ssh", "credential-access"],
                        )
                    )
                    break  # one alert per offending IP is enough
        return alerts


class CompromisedAccountDetector:
    """Flags a successful login that immediately follows a burst of failures
    from the same source IP — a strong signal the credential was cracked
    rather than mistyped.
    """

    rule_id = "SSH-002"

    def __init__(self, threshold: int = 3, window: timedelta = timedelta(minutes=5)):
        self.threshold = threshold
        self.window = window

    def run(self, events: list[LogEvent]) -> list[Alert]:
        events_sorted = sorted(events, key=lambda e: e.timestamp)
        alerts: list[Alert] = []
        for event in events_sorted:
            if event.action != "accepted_login":
                continue
            prior_failures = [
                e
                for e in events_sorted
                if e.action == "failed_password"
                and e.source_ip == event.source_ip
                and timedelta(0) <= event.timestamp - e.timestamp <= self.window
            ]
            if len(prior_failures) >= self.threshold:
                alerts.append(
                    Alert(
                        rule_id=self.rule_id,
                        title="Successful login following brute-force pattern",
                        severity=Severity.CRITICAL,
                        description=(
                            f"User '{event.user}' successfully authenticated from "
                            f"{event.source_ip} after {len(prior_failures)} failed attempts "
                            "from the same address — likely a compromised credential."
                        ),
                        events=[*prior_failures, event],
                        tags=["valid-account", "compromise", "ssh", "initial-access"],
                    )
                )
        return alerts


class OffHoursLoginDetector:
    """Flags accepted logins outside a configurable business-hours window."""

    rule_id = "SSH-003"

    def __init__(self, start_hour: int = 8, end_hour: int = 20):
        self.start_hour = start_hour
        self.end_hour = end_hour

    def run(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            if event.action != "accepted_login":
                continue
            if not (self.start_hour <= event.timestamp.hour < self.end_hour):
                alerts.append(
                    Alert(
                        rule_id=self.rule_id,
                        title="Off-hours login",
                        severity=Severity.MEDIUM,
                        description=(
                            f"User '{event.user}' logged in from {event.source_ip} at "
                            f"{event.timestamp.strftime('%H:%M')}, outside the "
                            f"{self.start_hour:02d}:00-{self.end_hour:02d}:00 business-hours window."
                        ),
                        events=[event],
                        tags=["off-hours", "anomalous", "unusual-time"],
                    )
                )
        return alerts


class PrivilegedAccountLoginDetector:
    """Flags direct logins to well-known privileged accounts."""

    rule_id = "SSH-004"
    default_privileged_users = frozenset({"root", "admin", "administrator"})

    def __init__(self, privileged_users: frozenset[str] | None = None):
        self.privileged_users = privileged_users or self.default_privileged_users

    def run(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            if event.action == "accepted_login" and event.user.lower() in self.privileged_users:
                alerts.append(
                    Alert(
                        rule_id=self.rule_id,
                        title="Privileged account login",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Privileged account '{event.user}' logged in directly "
                            f"from {event.source_ip}."
                        ),
                        events=[event],
                        tags=["root", "privileged", "local-account"],
                    )
                )
        return alerts


DEFAULT_DETECTORS = [
    BruteForceDetector(),
    CompromisedAccountDetector(),
    OffHoursLoginDetector(),
    PrivilegedAccountLoginDetector(),
]


def run_all_detectors(events: list[LogEvent], detectors: list | None = None) -> list[Alert]:
    """Run every detector (or a custom set) against the given events and
    return the combined, unordered list of alerts.
    """
    active_detectors = DEFAULT_DETECTORS if detectors is None else detectors
    alerts: list[Alert] = []
    for detector in active_detectors:
        alerts.extend(detector.run(events))
    return alerts
