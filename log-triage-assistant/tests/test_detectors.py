from datetime import datetime, timedelta
from pathlib import Path

from logtriage.detectors import (
    detect_brute_force,
    detect_compromise_after_brute_force,
    detect_persistence,
    detect_privilege_escalation,
    run_all_detectors,
)
from logtriage.parser import Event, parse_file
from logtriage.scoring import Severity

FIXTURES = Path(__file__).parent / "fixtures"
BASE = datetime(2026, 1, 10, 3, 0, 0)


def make_failed_login(offset_seconds: int, ip: str = "203.0.113.5", user: str = "root") -> Event:
    return Event(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        host="webserver",
        process="sshd",
        pid=1000 + offset_seconds,
        message=f"Failed password for {user} from {ip} port 50000 ssh2",
        raw="",
        kind="ssh_failed_password",
        fields={"user": user, "invalid_user": False, "ip": ip, "port": 50000},
    )


def make_accepted_login(offset_seconds: int, ip: str = "203.0.113.5", user: str = "root") -> Event:
    return Event(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        host="webserver",
        process="sshd",
        pid=2000 + offset_seconds,
        message=f"Accepted password for {user} from {ip} port 50001 ssh2",
        raw="",
        kind="ssh_accepted",
        fields={"user": user, "method": "password", "ip": ip, "port": 50001},
    )


def test_brute_force_fires_when_threshold_met_within_window():
    events = [make_failed_login(i * 8) for i in range(5)]  # 5 attempts across 32s
    findings = detect_brute_force(events, window_seconds=60, threshold=5)
    assert len(findings) == 1
    assert findings[0].type == "brute_force"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["ip"] == "203.0.113.5"
    assert findings[0].evidence["attempt_count"] == 5


def test_brute_force_does_not_fire_below_threshold():
    events = [make_failed_login(i * 8) for i in range(3)]
    findings = detect_brute_force(events, window_seconds=60, threshold=5)
    assert findings == []


def test_brute_force_does_not_fire_when_spread_outside_window():
    events = [make_failed_login(i * 30) for i in range(5)]  # 30s apart -> 120s span
    findings = detect_brute_force(events, window_seconds=60, threshold=5)
    assert findings == []


def test_compromise_after_brute_force_requires_prior_failures():
    failures = [make_failed_login(i * 5) for i in range(4)]
    success = make_accepted_login(30)
    findings = detect_compromise_after_brute_force(failures + [success])
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].evidence["prior_failed_attempts"] == 4


def test_compromise_after_brute_force_does_not_fire_with_isolated_success():
    success = make_accepted_login(0)
    findings = detect_compromise_after_brute_force([success])
    assert findings == []


def test_privilege_escalation_severity_escalates_when_correlated():
    from logtriage.detectors import Finding

    e = Event(
        timestamp=BASE + timedelta(seconds=100),
        host="webserver",
        process="sudo",
        pid=None,
        message="",
        raw="",
        kind="sudo_command",
        fields={"invoker": "ubuntu", "target_user": "root", "command": "/bin/bash"},
    )
    compromise = Finding(
        type="compromise_after_brute_force",
        severity=Severity.CRITICAL,
        title="t",
        description="d",
        evidence={},
        first_seen=BASE,
        last_seen=BASE + timedelta(seconds=50),
    )

    escalated = detect_privilege_escalation([e], prior_findings=[compromise])
    assert escalated[0].severity == Severity.CRITICAL
    assert escalated[0].evidence["correlated_with_compromise"] is True

    uncorrelated = detect_privilege_escalation([e], prior_findings=[])
    assert uncorrelated[0].severity == Severity.MEDIUM
    assert uncorrelated[0].evidence["correlated_with_compromise"] is False


def test_privilege_escalation_ignores_non_root_target():
    e = Event(
        timestamp=BASE,
        host="webserver",
        process="sudo",
        pid=None,
        message="",
        raw="",
        kind="sudo_command",
        fields={"invoker": "ubuntu", "target_user": "ubuntu", "command": "ls"},
    )
    assert detect_privilege_escalation([e]) == []


def test_persistence_detects_root_account_and_crontab():
    root_account = Event(
        timestamp=BASE,
        host="webserver",
        process="useradd",
        pid=None,
        message="",
        raw="",
        kind="useradd",
        fields={"name": "backdoor", "uid": 0},
    )
    normal_account = Event(
        timestamp=BASE,
        host="webserver",
        process="useradd",
        pid=None,
        message="",
        raw="",
        kind="useradd",
        fields={"name": "alice", "uid": 1001},
    )
    cron = Event(
        timestamp=BASE,
        host="webserver",
        process="crontab",
        pid=None,
        message="",
        raw="",
        kind="crontab_replace",
        fields={"user": "root", "action": "REPLACE"},
    )

    findings = detect_persistence([root_account, normal_account, cron])
    types = {f.type for f in findings}
    assert types == {"persistence_root_account", "persistence_crontab"}


def test_run_all_detectors_on_malicious_fixture():
    events = parse_file(FIXTURES / "sample_auth.log", default_year=2026)
    findings = run_all_detectors(events)
    types = {f.type for f in findings}

    assert "brute_force" in types
    assert "compromise_after_brute_force" in types
    assert "privilege_escalation" in types
    assert "persistence_root_account" in types
    assert "persistence_crontab" in types

    escalations = [f for f in findings if f.type == "privilege_escalation"]
    assert any(f.severity == Severity.CRITICAL for f in escalations)
    assert any(f.severity == Severity.MEDIUM for f in escalations)


def test_run_all_detectors_on_clean_fixture_finds_nothing():
    events = parse_file(FIXTURES / "sample_auth_clean.log", default_year=2026)
    findings = run_all_detectors(events)
    assert findings == []
