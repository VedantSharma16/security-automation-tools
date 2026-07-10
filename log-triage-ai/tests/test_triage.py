from datetime import datetime

from logtriage.models import Alert
from logtriage.triage import HeuristicTriageClient, TriageEngine


def _alert(**overrides):
    defaults = dict(
        id="brute-force-203.0.113.5",
        type="brute_force",
        severity="high",
        title="Brute-force SSH login attempts from 203.0.113.5",
        description="5 failed login attempts.",
        mitre_technique="T1110 - Brute Force",
        source_ip="203.0.113.5",
        related_raw=["line1", "line2"],
        first_seen=datetime(2026, 1, 10, 3, 14, 0),
        last_seen=datetime(2026, 1, 10, 3, 14, 20),
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_heuristic_triage_handles_no_alerts():
    report = HeuristicTriageClient().triage([])
    assert report.overall_severity == "low"
    assert report.alerts == []
    assert report.recommended_actions == []


def test_heuristic_triage_reports_highest_severity():
    alerts = [
        _alert(severity="high"),
        _alert(id="credential-compromise-203.0.113.5", type="credential_compromise", severity="critical"),
    ]
    report = HeuristicTriageClient().triage(alerts)

    assert report.overall_severity == "critical"
    assert len(report.alerts) == 2
    assert {a.severity for a in report.alerts} == {"high", "critical"}


def test_heuristic_triage_recommends_blocking_offending_ip():
    alerts = [_alert()]
    report = HeuristicTriageClient().triage(alerts)

    assert any("203.0.113.5" in action for action in report.recommended_actions)


def test_heuristic_triage_recommends_credential_reset_on_compromise():
    alerts = [_alert(id="credential-compromise-1", type="credential_compromise", severity="critical")]
    report = HeuristicTriageClient().triage(alerts)

    assert any("reset" in action.lower() for action in report.recommended_actions)


def test_triage_engine_end_to_end_with_heuristic_client():
    lines = [
        "Jan 10 03:14:01 web01 sshd[2001]: Failed password for invalid user admin from 203.0.113.5 port 51501 ssh2\n",
        "Jan 10 03:14:05 web01 sshd[2002]: Failed password for invalid user admin from 203.0.113.5 port 51502 ssh2\n",
        "Jan 10 03:14:09 web01 sshd[2003]: Failed password for invalid user root from 203.0.113.5 port 51503 ssh2\n",
        "Jan 10 03:14:13 web01 sshd[2004]: Failed password for invalid user root from 203.0.113.5 port 51504 ssh2\n",
        "Jan 10 03:14:17 web01 sshd[2005]: Failed password for invalid user oracle from 203.0.113.5 port 51505 ssh2\n",
        "Jan 10 03:14:40 web01 sshd[2006]: Accepted password for root from 203.0.113.5 port 51507 ssh2\n",
    ]
    engine = TriageEngine(triage_client=HeuristicTriageClient(), year=2026)
    events, alerts, report = engine.analyze(lines)

    assert len(events) == 6
    types = {a.type for a in alerts}
    assert "brute_force" in types
    assert "credential_compromise" in types
    assert report.overall_severity == "critical"
