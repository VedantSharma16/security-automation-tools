from datetime import datetime, timedelta

from logtriage.detectors import (
    BruteForceDetector,
    CredentialCompromiseDetector,
    PrivilegeEscalationDetector,
    run_detectors,
)
from logtriage.models import EventType, LogEvent

BASE = datetime(2026, 1, 10, 3, 14, 0)


def _event(event_type, seconds_offset=0, **kwargs):
    return LogEvent(
        timestamp=BASE + timedelta(seconds=seconds_offset),
        host="web01",
        process="sshd",
        raw=f"<synthetic event at +{seconds_offset}s>",
        event_type=event_type,
        **kwargs,
    )


def test_brute_force_triggers_at_threshold():
    events = [
        _event(EventType.AUTH_FAILURE, i * 4, source_ip="203.0.113.5", user="admin")
        for i in range(5)
    ]
    alerts = BruteForceDetector(threshold=5, window=timedelta(seconds=60)).detect(events)

    assert len(alerts) == 1
    assert alerts[0].source_ip == "203.0.113.5"
    assert alerts[0].type == "brute_force"
    assert alerts[0].mitre_technique.startswith("T1110")


def test_brute_force_does_not_trigger_below_threshold():
    events = [
        _event(EventType.AUTH_FAILURE, i * 4, source_ip="203.0.113.5", user="admin")
        for i in range(4)
    ]
    alerts = BruteForceDetector(threshold=5, window=timedelta(seconds=60)).detect(events)
    assert alerts == []


def test_brute_force_ignores_attempts_outside_window():
    # 5 failures, but spread over 10 minutes -- not a burst.
    events = [
        _event(EventType.AUTH_FAILURE, i * 150, source_ip="203.0.113.5", user="admin")
        for i in range(5)
    ]
    alerts = BruteForceDetector(threshold=5, window=timedelta(seconds=60)).detect(events)
    assert alerts == []


def test_credential_compromise_after_burst_of_failures():
    events = [
        _event(EventType.AUTH_FAILURE, i * 4, source_ip="203.0.113.5", user="root")
        for i in range(4)
    ]
    events.append(_event(EventType.AUTH_SUCCESS, 30, source_ip="203.0.113.5", user="root"))

    alerts = CredentialCompromiseDetector(min_prior_failures=3).detect(events)

    assert len(alerts) == 1
    assert alerts[0].type == "credential_compromise"
    assert alerts[0].severity == "critical"
    assert alerts[0].mitre_technique.startswith("T1078")


def test_no_credential_compromise_without_prior_failures():
    events = [_event(EventType.AUTH_SUCCESS, 0, source_ip="10.0.0.5", user="deploy")]
    alerts = CredentialCompromiseDetector(min_prior_failures=3).detect(events)
    assert alerts == []


def test_no_credential_compromise_when_success_is_too_late():
    events = [
        _event(EventType.AUTH_FAILURE, i * 4, source_ip="203.0.113.5", user="root")
        for i in range(4)
    ]
    # success arrives an hour later -- well outside the lookback window
    events.append(_event(EventType.AUTH_SUCCESS, 3600, source_ip="203.0.113.5", user="root"))

    alerts = CredentialCompromiseDetector(
        min_prior_failures=3, lookback=timedelta(minutes=10)
    ).detect(events)
    assert alerts == []


def test_privilege_escalation_flags_suid_chmod():
    events = [
        LogEvent(
            timestamp=BASE,
            host="web01",
            process="sudo",
            raw="synthetic sudo line",
            event_type=EventType.SUDO_COMMAND,
            user="root",
            command="/bin/chmod 4755 /bin/bash",
        )
    ]
    alerts = PrivilegeEscalationDetector().detect(events)
    assert len(alerts) == 1
    assert alerts[0].type == "privilege_escalation"
    assert alerts[0].mitre_technique.startswith("T1548")


def test_privilege_escalation_ignores_benign_sudo():
    events = [
        LogEvent(
            timestamp=BASE,
            host="web01",
            process="sudo",
            raw="synthetic sudo line",
            event_type=EventType.SUDO_COMMAND,
            user="deploy",
            command="/usr/bin/systemctl restart app",
        )
    ]
    alerts = PrivilegeEscalationDetector().detect(events)
    assert alerts == []


def test_run_detectors_combines_all_default_detectors():
    events = [
        _event(EventType.AUTH_FAILURE, i * 4, source_ip="203.0.113.5", user="admin")
        for i in range(5)
    ]
    events.append(
        LogEvent(
            timestamp=BASE + timedelta(seconds=30),
            host="web01",
            process="sudo",
            raw="synthetic sudo line",
            event_type=EventType.SUDO_COMMAND,
            user="root",
            command="usermod -aG sudo attacker",
        )
    )

    alerts = run_detectors(events)
    types = {a.type for a in alerts}
    assert "brute_force" in types
    assert "privilege_escalation" in types
