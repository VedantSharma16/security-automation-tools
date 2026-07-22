from pathlib import Path

from ir_agent.agent import IncidentResponseAgent

SAMPLE_INCIDENT = (Path(__file__).resolve().parent.parent / "examples" / "sample_incident.txt").read_text()


def test_offline_agent_is_not_live_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    agent = IncidentResponseAgent(api_key=None)
    assert agent.is_live is False


def test_offline_pipeline_flags_critical_incident():
    agent = IncidentResponseAgent(api_key=None)
    result = agent.investigate(SAMPLE_INCIDENT)

    assert result.mode == "offline"
    assert result.severity == "critical"
    assert "45.148.10.94" in result.key_indicators
    assert "T1110" in result.attack_techniques
    assert any("isolate" in action.lower() for action in result.recommended_actions)

    tool_names = [call.tool for call in result.transcript]
    assert tool_names == [
        "extract_iocs",
        "enrich_indicators",
        "analyze_auth_log",
        "map_attack_techniques",
    ]


def test_offline_pipeline_skips_log_analysis_when_no_log_lines():
    agent = IncidentResponseAgent(api_key=None)
    result = agent.investigate("A user reported a suspicious email from secure-login-verify.net.")

    tool_names = [call.tool for call in result.transcript]
    assert "analyze_auth_log" not in tool_names
    assert result.severity == "high"  # secure-login-verify.net is a known-malicious domain


def test_offline_pipeline_is_low_severity_for_clean_text():
    agent = IncidentResponseAgent(api_key=None)
    result = agent.investigate("Routine maintenance window completed with no issues.")
    assert result.severity == "low"
    assert result.key_indicators == []


def test_offline_result_round_trips_to_dict():
    agent = IncidentResponseAgent(api_key=None)
    result = agent.investigate(SAMPLE_INCIDENT)
    payload = result.to_dict()
    assert payload["severity"] == "critical"
    assert isinstance(payload["transcript"], list)
    assert payload["transcript"][0]["tool"] == "extract_iocs"
