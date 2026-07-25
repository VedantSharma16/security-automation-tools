from pathlib import Path

from agentic_soc.offline_agent import OfflineAgent
from agentic_soc.transcript import VERDICT_BENIGN, VERDICT_MALICIOUS

SAMPLE_ALERT = (Path(__file__).resolve().parent.parent / "examples" / "sample_alert.txt").read_text()


def test_offline_agent_flags_sample_alert_as_malicious():
    transcript = OfflineAgent().investigate(SAMPLE_ALERT)
    assert transcript.llm_backed is False
    assert transcript.verdict.verdict == VERDICT_MALICIOUS
    assert transcript.verdict.confidence >= 0.75


def test_offline_agent_calls_expected_tools_for_sample_alert():
    transcript = OfflineAgent().investigate(SAMPLE_ALERT)
    tools_called = [step.tool for step in transcript.steps]
    assert "lookup_ioc" in tools_called
    assert "check_process" in tools_called
    assert "get_asset_criticality" in tools_called
    assert "lookup_attack_technique" in tools_called
    assert transcript.steps_used == len(tools_called)


def test_offline_agent_records_hostname_and_indicator_values():
    transcript = OfflineAgent().investigate(SAMPLE_ALERT)
    indicator_values = {
        step.tool_input["indicator"] for step in transcript.steps if step.tool == "lookup_ioc"
    }
    assert "91.203.145.12" in indicator_values
    assert "secure-billing-portal.net" in indicator_values

    asset_steps = [step for step in transcript.steps if step.tool == "get_asset_criticality"]
    assert asset_steps[0].tool_input["hostname"] == "WKSTN-FIN-017"


def test_offline_agent_benign_for_clean_alert():
    clean_alert = (
        "Login Alert #001\n"
        "Host: KIOSK-LOBBY-01\n"
        "User visitor logged into the lobby kiosk from an internal IP during business hours. "
        "No unusual activity detected."
    )
    transcript = OfflineAgent().investigate(clean_alert)
    assert transcript.verdict.verdict == VERDICT_BENIGN
    assert "close the alert" in transcript.verdict.recommended_actions[0].lower()


def test_offline_agent_recommended_actions_match_verdict():
    transcript = OfflineAgent().investigate(SAMPLE_ALERT)
    assert any("isolate" in a.lower() for a in transcript.verdict.recommended_actions)
