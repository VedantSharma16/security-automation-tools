import json

from soc_agent.models import AgentResult, AgentStep
from soc_agent.report import render_human, render_json

RESULT = AgentResult(
    alert_id="ALT-1001",
    verdict="escalate",
    reason="Risk score 95/100 (escalate). Indicator 203.0.113.77 is known malicious.",
    backend="deterministic",
    steps=[
        AgentStep(
            step_number=1,
            tool_name="lookup_ioc_reputation",
            tool_args={"indicator": "203.0.113.77"},
            tool_result={"indicator": "203.0.113.77", "known_malicious": True, "confidence": "high"},
            thought="Check reputation of the observed indicator.",
        ),
        AgentStep(
            step_number=2,
            tool_name="escalate",
            tool_args={"reason": "Confirmed malicious indicator."},
            tool_result={"verdict": "escalate", "reason": "Confirmed malicious indicator."},
        ),
    ],
)


def test_render_human_includes_verdict_and_steps():
    text = render_human(RESULT)
    assert "ALT-1001" in text
    assert "ESCALATE" in text
    assert "lookup_ioc_reputation" in text
    assert "Check reputation of the observed indicator." in text
    assert "Risk score 95/100" in text


def test_render_json_round_trips_result():
    payload = json.loads(render_json(RESULT))
    assert payload["alert_id"] == "ALT-1001"
    assert payload["verdict"] == "escalate"
    assert len(payload["steps"]) == 2
    assert payload["steps"][0]["tool_name"] == "lookup_ioc_reputation"
