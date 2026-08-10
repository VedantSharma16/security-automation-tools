import json

from webauditor.findings import Finding, Severity
from webauditor.report import build_report, render_console, render_json


def make_finding(severity, id_):
    return Finding(
        id=id_, title=f"Title {id_}", severity=severity, category="cat",
        description="desc", recommendation="fix it", evidence="ev",
    )


def test_build_report_orders_findings_by_severity_desc():
    findings = [
        make_finding(Severity.LOW, "A"),
        make_finding(Severity.CRITICAL, "B"),
        make_finding(Severity.INFO, "C"),
        make_finding(Severity.HIGH, "D"),
    ]
    report = build_report("https://example.com", findings, "2026-01-01T00:00:00+00:00")
    severities = [f["severity"] for f in report["findings"]]
    assert severities == ["CRITICAL", "HIGH", "LOW", "INFO"]


def test_build_report_includes_target_and_timestamp():
    report = build_report("https://example.com", [], "2026-01-01T00:00:00+00:00")
    assert report["target"] == "https://example.com"
    assert report["generated_at"] == "2026-01-01T00:00:00+00:00"
    assert report["summary"]["total_findings"] == 0


def test_render_json_round_trips():
    report = build_report("https://example.com", [make_finding(Severity.HIGH, "A")], "now")
    parsed = json.loads(render_json(report))
    assert parsed == report


def test_render_console_mentions_target_and_no_issues_message():
    report = build_report("https://example.com", [], "now")
    output = render_console(report)
    assert "https://example.com" in output
    assert "No issues detected" in output


def test_render_console_includes_finding_details():
    report = build_report("https://example.com", [make_finding(Severity.CRITICAL, "X")], "now")
    output = render_console(report)
    assert "Title X" in output
    assert "fix it" in output
    assert "[CRITICAL]" in output
