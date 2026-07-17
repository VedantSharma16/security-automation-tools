from datetime import datetime, timedelta

from log_triage_agent.detectors import (
    DetectorConfig,
    detect_brute_force,
    detect_invalid_user_enumeration,
    detect_successful_login_after_brute_force,
    detect_sudo_privilege_escalation,
    run_all_detectors,
)
from log_triage_agent.models import Event, EventType, Severity

BASE = datetime(2024, 3, 4, 2, 0, 0)


def make_event(offset_seconds, event_type, source_ip=None, username=None, extra=None):
    return Event(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        host="web01",
        process="sshd",
        event_type=event_type,
        raw="synthetic",
        username=username,
        source_ip=source_ip,
        extra=extra or {},
    )


def test_brute_force_detected_when_threshold_met_within_window():
    events = [
        make_event(i * 10, EventType.AUTH_FAILURE, source_ip="203.0.113.7", username="root")
        for i in range(5)
    ]
    findings = detect_brute_force(events, DetectorConfig(brute_force_window_minutes=10, brute_force_threshold=5))

    assert len(findings) == 1
    assert findings[0].source_ip == "203.0.113.7"
    assert findings[0].technique_id == "T1110"
    assert findings[0].event_count == 5


def test_brute_force_not_flagged_below_threshold():
    events = [
        make_event(i * 10, EventType.AUTH_FAILURE, source_ip="203.0.113.7", username="root")
        for i in range(3)
    ]
    findings = detect_brute_force(events, DetectorConfig(brute_force_threshold=5))
    assert findings == []


def test_brute_force_not_flagged_when_spread_outside_window():
    events = [
        make_event(i * 3600, EventType.AUTH_FAILURE, source_ip="203.0.113.7", username="root")
        for i in range(5)
    ]
    findings = detect_brute_force(events, DetectorConfig(brute_force_window_minutes=10, brute_force_threshold=5))
    assert findings == []


def test_invalid_user_enumeration_detected():
    events = [
        make_event(i * 5, EventType.INVALID_USER, source_ip="198.51.100.44", username=f"user{i}")
        for i in range(4)
    ]
    findings = detect_invalid_user_enumeration(events, DetectorConfig(invalid_user_threshold=3))

    assert len(findings) == 1
    assert findings[0].technique_id == "T1087"
    assert findings[0].event_count == 4


def test_successful_login_after_brute_force_flagged_critical():
    bf_events = [
        make_event(i * 10, EventType.AUTH_FAILURE, source_ip="203.0.113.7", username="deploy")
        for i in range(5)
    ]
    success = make_event(120, EventType.AUTH_SUCCESS, source_ip="203.0.113.7", username="deploy")
    bf_findings = detect_brute_force(bf_events, DetectorConfig())

    findings = detect_successful_login_after_brute_force(bf_events + [success], bf_findings)

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].technique_id == "T1078"
    assert findings[0].username == "deploy"


def test_successful_login_from_clean_ip_not_flagged():
    success = make_event(0, EventType.AUTH_SUCCESS, source_ip="10.0.0.15", username="alice")
    findings = detect_successful_login_after_brute_force([success], brute_force_findings=[])
    assert findings == []


def test_sudo_privilege_escalation_flags_risky_command():
    event = make_event(
        0,
        EventType.SUDO_COMMAND,
        username="deploy",
        extra={"target_user": "root", "command": "/bin/bash"},
    )
    findings = detect_sudo_privilege_escalation([event])

    assert len(findings) == 1
    assert findings[0].technique_id == "T1548.003"


def test_sudo_ignores_benign_command():
    event = make_event(
        0,
        EventType.SUDO_COMMAND,
        username="alice",
        extra={"target_user": "root", "command": "/usr/bin/systemctl restart nginx"},
    )
    findings = detect_sudo_privilege_escalation([event])
    assert findings == []


def test_run_all_detectors_orders_by_severity_desc():
    bf_events = [
        make_event(i * 10, EventType.AUTH_FAILURE, source_ip="203.0.113.7", username="root")
        for i in range(5)
    ]
    success = make_event(120, EventType.AUTH_SUCCESS, source_ip="203.0.113.7", username="deploy")
    sudo_event = make_event(
        200,
        EventType.SUDO_COMMAND,
        username="alice",
        extra={"target_user": "root", "command": "/usr/bin/passwd root"},
    )

    findings = run_all_detectors(bf_events + [success, sudo_event])

    severities = [f.severity.rank for f in findings]
    assert severities == sorted(severities, reverse=True)
    assert findings[0].severity == Severity.CRITICAL
