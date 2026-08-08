import json

from investigator import planner, report
from investigator.state import Alert


def _result():
    alert = Alert(
        alert_id="ALT-900",
        description="Multiple failed login attempts, password spray pattern observed.",
        indicators=["185.220.101.45"],
        host="fin-db-03",
    )
    return planner.run(alert)


def test_to_json_round_trips():
    result = _result()
    payload = json.loads(report.to_json(result))
    assert payload["alert"]["alert_id"] == "ALT-900"
    assert payload["verdict"] == result.verdict
    assert len(payload["trace"]) == len(result.trace)


def test_to_markdown_contains_key_sections():
    result = _result()
    md = report.to_markdown(result)
    assert "# Investigation Report: ALT-900" in md
    assert "## Alert" in md
    assert "## Summary" in md
    assert "## Investigation Trace" in md
    assert "## Recommended Actions" in md
    assert "TRUE POSITIVE" in md


def test_to_markdown_handles_empty_trace_and_actions():
    from investigator.state import InvestigationResult

    result = InvestigationResult(
        alert=Alert(alert_id="EMPTY", description="d"),
        trace=[],
        risk_score=0,
        risk_band="low",
        verdict="false_positive",
        confidence="low",
        summary="Nothing to report.",
        recommended_actions=[],
        mode="offline_planner",
    )
    md = report.to_markdown(result)
    assert "No tool calls were made." in md
    assert "- None." in md
