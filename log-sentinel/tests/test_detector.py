from datetime import datetime, timedelta

from log_sentinel.detector import DetectorConfig, FindingType, Severity, detect
from log_sentinel.parser import EventType, LogEntry

BASE = datetime(2026, 7, 14, 3, 0, 0)


def entry(event, user, ip, seconds_offset=0, port=51000):
    return LogEntry(
        timestamp=BASE + timedelta(seconds=seconds_offset),
        event=event,
        user=user,
        source_ip=ip,
        port=port,
        raw=f"<synthetic {event} {user}@{ip}>",
    )


def test_brute_force_detected_within_window():
    entries = [
        entry(EventType.FAILED_PASSWORD, "root", "203.0.113.55", i * 5) for i in range(5)
    ]
    findings = detect(entries, DetectorConfig(brute_force_threshold=5, brute_force_window_seconds=60))
    brute = [f for f in findings if f.type == FindingType.BRUTE_FORCE]
    assert len(brute) == 1
    assert brute[0].source_ip == "203.0.113.55"
    assert brute[0].count == 5
    assert brute[0].severity == Severity.HIGH


def test_brute_force_escalates_to_critical_at_double_threshold():
    entries = [
        entry(EventType.FAILED_PASSWORD, "root", "203.0.113.55", i * 5) for i in range(10)
    ]
    findings = detect(entries, DetectorConfig(brute_force_threshold=5, brute_force_window_seconds=60))
    brute = [f for f in findings if f.type == FindingType.BRUTE_FORCE]
    assert brute[0].severity == Severity.CRITICAL


def test_brute_force_not_triggered_below_threshold():
    entries = [
        entry(EventType.FAILED_PASSWORD, "root", "203.0.113.55", i * 5) for i in range(4)
    ]
    findings = detect(entries, DetectorConfig(brute_force_threshold=5, brute_force_window_seconds=60))
    assert not [f for f in findings if f.type == FindingType.BRUTE_FORCE]


def test_brute_force_not_triggered_when_spread_outside_window():
    entries = [
        entry(EventType.FAILED_PASSWORD, "root", "203.0.113.55", i * 150) for i in range(5)
    ]
    findings = detect(entries, DetectorConfig(brute_force_threshold=5, brute_force_window_seconds=60))
    assert not [f for f in findings if f.type == FindingType.BRUTE_FORCE]


def test_credential_compromise_suspected_after_failed_then_accepted():
    entries = [
        entry(EventType.FAILED_PASSWORD, "root", "203.0.113.55", 0),
        entry(EventType.FAILED_PASSWORD, "root", "203.0.113.55", 5),
        entry(EventType.ACCEPTED, "root", "203.0.113.55", 10),
    ]
    findings = detect(entries)
    compromise = [f for f in findings if f.type == FindingType.CREDENTIAL_COMPROMISE_SUSPECTED]
    assert len(compromise) == 1
    assert compromise[0].source_ip == "203.0.113.55"


def test_no_compromise_finding_for_clean_accepted_login():
    entries = [entry(EventType.ACCEPTED, "deploy", "198.51.100.20", 0)]
    findings = detect(entries, DetectorConfig(off_hours_start=0, off_hours_end=24))
    assert not findings


def test_user_enumeration_detected():
    entries = [
        entry(EventType.INVALID_USER, "admin", "203.0.113.55", 0),
        entry(EventType.INVALID_USER, "test", "203.0.113.55", 3),
        entry(EventType.INVALID_USER, "oracle", "203.0.113.55", 6),
    ]
    findings = detect(entries, DetectorConfig(enumeration_threshold=3))
    enum_findings = [f for f in findings if f.type == FindingType.USER_ENUMERATION]
    assert len(enum_findings) == 1
    assert enum_findings[0].count == 3


def test_user_enumeration_not_triggered_below_threshold():
    entries = [
        entry(EventType.INVALID_USER, "admin", "203.0.113.55", 0),
        entry(EventType.INVALID_USER, "test", "203.0.113.55", 3),
    ]
    findings = detect(entries, DetectorConfig(enumeration_threshold=3))
    assert not [f for f in findings if f.type == FindingType.USER_ENUMERATION]


def test_anomalous_login_time_outside_business_hours():
    entries = [entry(EventType.ACCEPTED, "backup", "198.51.100.44", 0)]  # BASE hour = 3am
    findings = detect(entries, DetectorConfig(off_hours_start=6, off_hours_end=22))
    off_hours = [f for f in findings if f.type == FindingType.ANOMALOUS_LOGIN_TIME]
    assert len(off_hours) == 1
    assert off_hours[0].severity == Severity.LOW


def test_findings_sorted_by_severity_descending():
    entries = [
        entry(EventType.ACCEPTED, "backup", "198.51.100.44", 0),
        *[entry(EventType.FAILED_PASSWORD, "root", "203.0.113.55", i * 5) for i in range(10)],
    ]
    findings = detect(entries, DetectorConfig(brute_force_threshold=5, brute_force_window_seconds=60))
    assert findings[0].severity == Severity.CRITICAL
