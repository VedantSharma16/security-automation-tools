import json

from soc_agent.agent import AgentStep, InvestigationResult
from soc_agent.report import render_json, render_text, to_dict


def _sample_result():
    return InvestigationResult(
        alert_text="beacon to 185.220.101.1",
        steps=[
            AgentStep(
                step=1,
                thought="Checking IP reputation.",
                action="lookup_ip_reputation",
                action_input={"ip": "185.220.101.1"},
                observation={"verdict": "malicious", "confidence": "high"},
            )
        ],
        verdict="malicious",
        severity="critical",
        confidence="high",
        summary="Confirmed C2 beaconing.",
        recommended_actions=["Isolate host"],
        llm_backed=False,
    )


def test_to_dict_shape():
    d = to_dict(_sample_result())
    assert d["verdict"] == "malicious"
    assert d["steps"][0]["action"] == "lookup_ip_reputation"
    assert d["recommended_actions"] == ["Isolate host"]


def test_render_json_round_trips():
    parsed = json.loads(render_json(_sample_result()))
    assert parsed["severity"] == "critical"
    assert parsed["llm_backed"] is False


def test_render_text_includes_verdict_summary_and_trace():
    text = render_text(_sample_result())
    assert "MALICIOUS" in text
    assert "CRITICAL" in text
    assert "Confirmed C2 beaconing." in text
    assert "Isolate host" in text
    assert "lookup_ip_reputation" in text


def test_render_text_can_hide_trace():
    text = render_text(_sample_result(), show_trace=False)
    assert "Investigation trace" not in text
    assert "Confirmed C2 beaconing." in text
