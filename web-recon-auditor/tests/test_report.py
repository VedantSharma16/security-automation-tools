import json

from webrecon.findings import Finding
from webrecon.report import render, to_json, to_markdown
from webrecon.scanner import ScanReport
from webrecon.scoring import assess_risk


def _make_report(findings, summary=None, llm_backed=False, errors=None):
    risk = assess_risk(findings)
    return ScanReport(
        target="http://example.com",
        scanned_at="2026-01-01T00:00:00+00:00",
        findings=findings,
        risk=risk,
        llm_backed=llm_backed,
        summary=summary,
        errors=errors or [],
    )


def _finding(severity="high"):
    return Finding(
        id="missing-hsts",
        category="headers",
        severity=severity,
        title="Missing HSTS",
        detail="detail text",
        recommendation="set HSTS",
    )


def test_to_json_round_trips_core_fields():
    report = _make_report([_finding()])
    data = json.loads(to_json(report))
    assert data["target"] == "http://example.com"
    assert data["risk"]["overall_severity"] == "high"
    assert data["findings"][0]["id"] == "missing-hsts"
    assert data["llm_backed"] is False


def test_to_markdown_includes_target_and_findings():
    report = _make_report([_finding()])
    md = to_markdown(report)
    assert "example.com" in md
    assert "Missing HSTS" in md
    assert "set HSTS" in md


def test_to_markdown_no_findings_says_so():
    report = _make_report([])
    md = to_markdown(report)
    assert "No findings were raised" in md


def test_to_markdown_includes_summary_when_present():
    report = _make_report([_finding()], summary="Fix HSTS first.")
    md = to_markdown(report)
    assert "Executive summary" in md
    assert "Fix HSTS first." in md


def test_to_markdown_includes_errors_section():
    report = _make_report([], errors=["Could not reach http://example.com: timeout"])
    md = to_markdown(report)
    assert "## Errors" in md
    assert "timeout" in md


def test_render_dispatches_on_format():
    report = _make_report([_finding()])
    assert render(report, "json").startswith("{")
    assert render(report, "markdown").startswith("# Attack Surface Report")


def test_render_rejects_unknown_format():
    report = _make_report([])
    try:
        render(report, "xml")
        assert False, "expected ValueError"
    except ValueError:
        pass
