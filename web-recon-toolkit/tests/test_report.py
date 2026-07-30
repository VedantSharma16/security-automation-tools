import json

from webrecon.models import Finding, ScanResult, Severity
from webrecon.report import build_report, to_json, to_markdown


def _result(findings):
    return ScanResult(
        target="http://example.test",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:05+00:00",
        findings=findings,
        errors=[],
    )


def test_build_report_sorts_findings_worst_first():
    low = Finding(id="a", title="low", severity=Severity.LOW, category="x", description="d")
    critical = Finding(id="b", title="crit", severity=Severity.CRITICAL, category="x", description="d")
    report = build_report(_result([low, critical]))
    assert [f["id"] for f in report["findings"]] == ["b", "a"]


def test_build_report_summary_matches_scoring():
    high = Finding(id="a", title="t", severity=Severity.HIGH, category="x", description="d")
    report = build_report(_result([high]))
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["highest_severity"] == "HIGH"
    assert report["summary"]["risk_score"] == 30


def test_to_json_round_trips():
    report = build_report(_result([]))
    parsed = json.loads(to_json(report))
    assert parsed["target"] == "http://example.test"


def test_to_markdown_no_findings():
    report = build_report(_result([]))
    md = to_markdown(report)
    assert "No findings" in md


def test_to_markdown_includes_finding_details():
    finding = Finding(
        id="a",
        title="Missing HSTS",
        severity=Severity.MEDIUM,
        category="headers",
        description="No HSTS header set.",
        evidence="none",
        remediation="Add the header.",
        owasp_ref="A05:2021",
    )
    md = to_markdown(build_report(_result([finding])))
    assert "[MEDIUM] Missing HSTS" in md
    assert "Add the header." in md
    assert "A05:2021" in md
