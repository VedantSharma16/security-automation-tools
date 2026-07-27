import json
from pathlib import Path

import pytest

from soc_agent.agent import SecOpsAgent
from soc_agent.playbook import AlertCase

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _load_alert(filename: str) -> AlertCase:
    data = json.loads((EXAMPLES_DIR / filename).read_text())
    return AlertCase.from_dict(data)


@pytest.fixture
def agent():
    return SecOpsAgent(api_key=None)


def test_agent_without_api_key_is_not_live(agent):
    assert agent.is_live is False


def test_c2_beacon_alert_is_malicious(agent):
    alert = _load_alert("alert_c2_beacon.json")
    report = agent.investigate(alert)

    assert report.mode == "offline"
    assert report.verdict == "malicious"
    assert report.confidence == "high"
    tool_names = {step.tool for step in report.trace}
    assert tool_names == {
        "lookup_asset_criticality",
        "lookup_ioc_reputation",
        "lookup_user_risk",
        "check_process_baseline",
    }
    assert any("KNOWN MALICIOUS" in e for e in report.evidence)
    assert any("isolate" in a.lower() for a in report.recommended_actions)


def test_benign_login_alert_is_benign(agent):
    alert = _load_alert("alert_benign_login.json")
    report = agent.investigate(alert)

    assert report.verdict == "benign"
    assert report.confidence == "low"
    assert "close the alert as benign" in report.recommended_actions[0].lower()


def test_suspicious_scan_alert_is_suspicious_or_worse(agent):
    alert = _load_alert("alert_suspicious_scan.json")
    report = agent.investigate(alert)

    assert report.verdict in {"suspicious", "malicious"}
    assert any("svc_backup" in e for e in report.evidence)
    # No hostname+process_name pair on this alert, so the process baseline tool
    # should never be invoked.
    assert "check_process_baseline" not in {step.tool for step in report.trace}


def test_alert_with_no_optional_fields_produces_no_tool_calls_and_is_benign(agent):
    alert = AlertCase(alert_id="ALT-EMPTY", description="No enrichable fields present.")
    report = agent.investigate(alert)

    assert report.trace == []
    assert report.verdict == "benign"
    assert "No relevant fields present" in report.evidence[0]


def test_score_to_verdict_boundaries():
    assert SecOpsAgent._score_to_verdict(0) == ("benign", "low")
    assert SecOpsAgent._score_to_verdict(29) == ("benign", "low")
    assert SecOpsAgent._score_to_verdict(30) == ("suspicious", "medium")
    assert SecOpsAgent._score_to_verdict(59) == ("suspicious", "medium")
    assert SecOpsAgent._score_to_verdict(60) == ("malicious", "high")
