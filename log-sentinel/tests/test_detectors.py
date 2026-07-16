from datetime import datetime, timedelta

from log_sentinel.detectors import (
    BruteForceDetector,
    CompromisedAccountDetector,
    OffHoursLoginDetector,
    PrivilegedAccountLoginDetector,
    run_all_detectors,
)
from log_sentinel.models import LogEvent, Severity


def make_event(action, user, ip, minute_offset, hour=3):
    return LogEvent(
        timestamp=datetime(2026, 7, 14, hour, 0, 0) + timedelta(minutes=minute_offset),
        host="web01",
        source_ip=ip,
        user=user,
        action=action,
        raw_line="synthetic",
    )


def test_brute_force_detector_triggers_on_threshold():
    events = [make_event("failed_password", "admin", "203.0.113.7", i) for i in range(5)]
    alerts = BruteForceDetector(threshold=5, window=timedelta(minutes=10)).run(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "SSH-001"
    assert alerts[0].severity == Severity.HIGH


def test_brute_force_detector_ignores_sparse_attempts():
    events = [make_event("failed_password", "admin", "203.0.113.7", i * 30) for i in range(5)]
    alerts = BruteForceDetector(threshold=5, window=timedelta(minutes=10)).run(events)
    assert alerts == []


def test_compromised_account_detector_flags_success_after_failures():
    events = [make_event("failed_password", "root", "203.0.113.7", i) for i in range(4)]
    events.append(make_event("accepted_login", "root", "203.0.113.7", 4))
    alerts = CompromisedAccountDetector(threshold=3, window=timedelta(minutes=10)).run(events)
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL
    assert "root" in alerts[0].users


def test_compromised_account_detector_ignores_isolated_success():
    events = [make_event("accepted_login", "jsmith", "10.0.0.44", 0)]
    alerts = CompromisedAccountDetector().run(events)
    assert alerts == []


def test_off_hours_login_detector_flags_late_night_only():
    late_event = make_event("accepted_login", "backupsvc", "198.51.100.22", 0, hour=23)
    business_event = make_event("accepted_login", "deploy", "10.0.0.5", 0, hour=10)
    alerts = OffHoursLoginDetector().run([late_event, business_event])
    assert len(alerts) == 1
    assert alerts[0].events[0].user == "backupsvc"


def test_privileged_account_login_detector():
    events = [
        make_event("accepted_login", "root", "203.0.113.7", 0),
        make_event("accepted_login", "jsmith", "10.0.0.44", 0),
    ]
    alerts = PrivilegedAccountLoginDetector().run(events)
    assert len(alerts) == 1
    assert alerts[0].events[0].user == "root"


def test_run_all_detectors_aggregates_results():
    events = [make_event("failed_password", "admin", "203.0.113.7", i) for i in range(5)]
    alerts = run_all_detectors(events)
    assert any(a.rule_id == "SSH-001" for a in alerts)
