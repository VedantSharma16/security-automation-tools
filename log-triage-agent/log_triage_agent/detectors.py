"""Rule-based detectors that turn a stream of parsed LogEvents into
Findings. Each detector is intentionally simple and independent so they can
be unit tested in isolation and composed freely by the agent pipeline.
"""

from collections import defaultdict
from datetime import timedelta
from typing import List

from .models import EventType, Finding, LogEvent, Severity

FAILED_TYPES = (EventType.FAILED_PASSWORD, EventType.INVALID_USER)


def _group_by_ip(events: List[LogEvent]) -> dict:
    grouped = defaultdict(list)
    for event in events:
        grouped[event.source_ip].append(event)
    for ip_events in grouped.values():
        ip_events.sort(key=lambda e: e.timestamp)
    return grouped


def _max_window_events(events: List[LogEvent], window: timedelta) -> List[LogEvent]:
    """Return the largest set of chronologically-sorted events that all
    fall within `window` of each other (sliding window over sorted events)."""
    best: List[LogEvent] = []
    left = 0
    for right in range(len(events)):
        while events[right].timestamp - events[left].timestamp > window:
            left += 1
        if right - left + 1 > len(best):
            best = events[left : right + 1]
    return best


def detect_brute_force(
    events: List[LogEvent],
    threshold: int = 5,
    window_minutes: int = 10,
) -> List[Finding]:
    """Flags source IPs with `threshold`+ failed logins within a rolling
    window -- the classic signature of automated password guessing
    (MITRE ATT&CK T1110)."""
    findings = []
    window = timedelta(minutes=window_minutes)
    failed_events = [e for e in events if e.event_type in FAILED_TYPES]

    for ip, ip_events in _group_by_ip(failed_events).items():
        burst = _max_window_events(ip_events, window)
        if len(burst) >= threshold:
            findings.append(
                Finding(
                    finding_type="brute_force",
                    severity=Severity.HIGH,
                    source_ip=ip,
                    summary=(
                        f"{len(burst)} failed login attempts from {ip} within "
                        f"{window_minutes} minutes."
                    ),
                    events=burst,
                    metadata={"attempt_count": len(burst)},
                )
            )
    return findings


def detect_password_spray(
    events: List[LogEvent],
    distinct_user_threshold: int = 4,
    window_minutes: int = 10,
) -> List[Finding]:
    """Flags source IPs attempting many distinct usernames in a short
    window -- password spraying rather than brute-forcing one account
    (MITRE ATT&CK T1110.003)."""
    findings = []
    window = timedelta(minutes=window_minutes)
    failed_events = [e for e in events if e.event_type in FAILED_TYPES]

    for ip, ip_events in _group_by_ip(failed_events).items():
        burst = _max_window_events(ip_events, window)
        distinct_users = {e.username for e in burst}
        if len(distinct_users) >= distinct_user_threshold:
            findings.append(
                Finding(
                    finding_type="password_spray",
                    severity=Severity.HIGH,
                    source_ip=ip,
                    summary=(
                        f"{ip} attempted {len(distinct_users)} distinct usernames "
                        f"within {window_minutes} minutes."
                    ),
                    events=burst,
                    metadata={"distinct_users": sorted(distinct_users)},
                )
            )
    return findings


def detect_credential_success_after_failures(
    events: List[LogEvent],
    min_prior_failures: int = 3,
    window_minutes: int = 10,
) -> List[Finding]:
    """Flags a successful login preceded by several failures from the same
    IP -- a strong indicator the account was actually compromised rather
    than the attacker giving up (MITRE ATT&CK T1078 - Valid Accounts)."""
    findings = []
    window = timedelta(minutes=window_minutes)

    for ip, ip_events in _group_by_ip(events).items():
        for i, event in enumerate(ip_events):
            if event.event_type != EventType.ACCEPTED_PASSWORD:
                continue
            prior_failures = [
                e
                for e in ip_events[:i]
                if e.event_type in FAILED_TYPES and event.timestamp - e.timestamp <= window
            ]
            if len(prior_failures) >= min_prior_failures:
                findings.append(
                    Finding(
                        finding_type="credential_success_after_failures",
                        severity=Severity.CRITICAL,
                        source_ip=ip,
                        summary=(
                            f"Successful login as '{event.username}' from {ip} after "
                            f"{len(prior_failures)} failed attempts."
                        ),
                        events=prior_failures + [event],
                        metadata={
                            "username": event.username,
                            "prior_failures": len(prior_failures),
                        },
                    )
                )
    return findings


def detect_off_hours_login(
    events: List[LogEvent],
    start_hour: int = 0,
    end_hour: int = 5,
) -> List[Finding]:
    """Flags successful logins that land inside an unusual hours window
    (default 00:00-05:00 local time). Not an ATT&CK technique by itself,
    but a common behavioral analytic used to prioritize triage."""
    findings = []
    for event in events:
        if event.event_type != EventType.ACCEPTED_PASSWORD:
            continue
        if start_hour <= event.timestamp.hour < end_hour:
            findings.append(
                Finding(
                    finding_type="off_hours_login",
                    severity=Severity.LOW,
                    source_ip=event.source_ip,
                    summary=(
                        f"Successful login as '{event.username}' from {event.source_ip} "
                        f"at {event.timestamp.strftime('%H:%M')} (outside business hours)."
                    ),
                    events=[event],
                    metadata={"username": event.username, "hour": event.timestamp.hour},
                )
            )
    return findings


DEFAULT_DETECTORS = (
    detect_brute_force,
    detect_password_spray,
    detect_credential_success_after_failures,
    detect_off_hours_login,
)


def run_all_detectors(events: List[LogEvent], detectors=DEFAULT_DETECTORS) -> List[Finding]:
    findings = []
    for detector in detectors:
        findings.extend(detector(events))
    return findings
