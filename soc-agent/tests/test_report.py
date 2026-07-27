import json

from soc_agent.playbook import AlertCase, IncidentReport, ToolCallRecord
from soc_agent.report import render_json, render_markdown


def _sample_report() -> IncidentReport:
    alert = AlertCase(
        alert_id="ALT-9",
        description="Test alert",
        hostname="db-primary.prod.internal",
        dest_ip="203.0.113.55",
    )
    trace = [
        ToolCallRecord(
            "lookup_ioc_reputation",
            {"indicator": "203.0.113.55"},
            {"verdict": "malicious", "notes": "Known C2."},
        )
    ]
    return IncidentReport(
        alert=alert,
        trace=trace,
        verdict="malicious",
        confidence="high",
        score=90,
        evidence=["203.0.113.55 is known-malicious."],
        recommended_actions=["Isolate the host."],
        mode="offline",
        warnings=["heads up"],
    )


def test_render_markdown_includes_key_sections():
    md = render_markdown(_sample_report())
    assert "# Incident Report — ALT-9" in md
    assert "MALICIOUS" in md
    assert "## Investigation trace" in md
    assert "lookup_ioc_reputation" in md
    assert "## Evidence" in md
    assert "## Recommended actions" in md
    assert "## Warnings" in md
    assert "heads up" in md


def test_render_markdown_omits_warnings_section_when_none():
    report = _sample_report()
    report.warnings = []
    md = render_markdown(report)
    assert "## Warnings" not in md


def test_render_markdown_shows_no_tool_calls_message_when_trace_empty():
    report = _sample_report()
    report.trace = []
    md = render_markdown(report)
    assert "(no tool calls made)" in md


def test_render_json_round_trips():
    report = _sample_report()
    payload = json.loads(render_json(report))
    assert payload["verdict"] == "malicious"
    assert payload["alert"]["alert_id"] == "ALT-9"
    assert payload["trace"][0]["tool"] == "lookup_ioc_reputation"
