import json

from httpsec.models import Finding
from httpsec.report import render_console, render_json, sort_findings
from httpsec.scoring import score_findings


def _finding(severity: str, fid: str) -> Finding:
    return Finding(
        id=fid,
        category="headers",
        severity=severity,
        title=f"title-{fid}",
        description="desc",
        remediation="fix it",
        evidence="ev",
    )


def test_sort_findings_orders_by_severity():
    findings = [_finding("low", "a"), _finding("critical", "b"), _finding("medium", "c")]
    ordered = sort_findings(findings)
    assert [f.severity for f in ordered] == ["critical", "medium", "low"]


def test_render_console_no_findings():
    text = render_console("https://example.com", [], score_findings([]), use_color=False)
    assert "No findings" in text
    assert "100" in text


def test_render_console_includes_finding_details_and_no_ansi_when_disabled():
    findings = [_finding("high", "x")]
    text = render_console("https://example.com", findings, score_findings(findings), use_color=False)
    assert "title-x" in text
    assert "fix it" in text
    assert "\033[" not in text


def test_render_console_uses_ansi_when_enabled():
    findings = [_finding("high", "x")]
    text = render_console("https://example.com", findings, score_findings(findings), use_color=True)
    assert "\033[" in text


def test_render_json_roundtrips_findings():
    findings = [_finding("critical", "x"), _finding("low", "y")]
    text = render_json("https://example.com", findings, score_findings(findings))
    payload = json.loads(text)
    assert payload["target"] == "https://example.com"
    assert payload["grade"] in "ABCDF"
    assert len(payload["findings"]) == 2
    assert payload["findings"][0]["severity"] == "critical"  # sorted first
