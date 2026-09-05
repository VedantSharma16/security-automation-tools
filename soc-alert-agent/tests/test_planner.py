import json
import os

from soc_agent.models import Alert
from soc_agent.planner import run_deterministic
from soc_agent.tools import ToolRegistry

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_QUEUE_PATH = os.path.join(PROJECT_ROOT, "examples", "sample_alerts.json")


def _load_queue():
    with open(SAMPLE_QUEUE_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _run(alert_id: str):
    raw_alerts = _load_queue()
    tools = ToolRegistry(alerts=raw_alerts)
    raw = next(a for a in raw_alerts if a["alert_id"] == alert_id)
    return run_deterministic(Alert.from_dict(raw), tools)


def test_confirmed_c2_beacon_on_crown_jewel_escalates():
    result = _run("ALT-1001")
    assert result.verdict == "escalate"
    assert result.backend == "deterministic"


def test_related_alert_from_same_campaign_also_escalates():
    result = _run("ALT-1002")
    assert result.verdict == "escalate"


def test_benign_internal_port_scan_on_low_criticality_host_closes():
    result = _run("ALT-1003")
    assert result.verdict == "close"


def test_ambiguous_brute_force_from_allowlisted_ip_goes_to_monitor():
    result = _run("ALT-1004")
    assert result.verdict == "monitor"


def test_every_alert_produces_a_terminal_step():
    for alert_id in ("ALT-1001", "ALT-1002", "ALT-1003", "ALT-1004"):
        result = _run(alert_id)
        assert result.steps, "expected at least one recorded step"
        last_step = result.steps[-1]
        assert last_step.tool_name == result.verdict


def test_reason_is_grounded_in_gathered_evidence():
    result = _run("ALT-1001")
    assert "203.0.113.77" in result.reason
    assert "crown_jewel" in result.reason
