import json

from recon_agent.models import Finding, ReconReport, ToolResult
from recon_agent.report import offline_narrative, to_json, to_markdown


def make_report(findings=None, narrative=""):
    findings = findings or []
    return ReconReport(
        target="example.com",
        tool_results=[ToolResult(tool="dns", data={"A": ["1.2.3.4"]}, findings=findings)],
        score=100 - sum({"critical": 30, "high": 15, "medium": 7, "low": 3, "info": 0}[f.severity] for f in findings),
        grade="A",
        narrative=narrative,
    )


def test_offline_narrative_reports_clean_scan():
    report = make_report()
    text = offline_narrative(report)
    assert "No security-relevant findings" in text
    assert "example.com" in text


def test_offline_narrative_summarizes_findings_by_severity_and_top_issue():
    findings = [
        Finding(tool="dns", severity="low", title="Minor issue", detail="d", recommendation="fix minor"),
        Finding(tool="tls", severity="critical", title="Expired cert", detail="d", recommendation="renew now"),
    ]
    report = make_report(findings)
    text = offline_narrative(report)
    assert "2 finding(s)" in text
    assert "1 critical" in text
    assert "Expired cert" in text
    assert "renew now" in text


def test_to_markdown_includes_score_findings_and_raw_data():
    findings = [Finding(tool="dns", severity="high", title="No HTTPS", detail="d", recommendation="r")]
    report = make_report(findings)
    md = to_markdown(report)
    assert "# Recon Report: example.com" in md
    assert f"{report.score}/100" in md
    assert "[HIGH] No HTTPS (dns)" in md
    assert '"A": [' in md


def test_to_markdown_uses_agent_narrative_when_present():
    report = make_report(narrative="Custom agent summary.")
    md = to_markdown(report)
    assert "Custom agent summary." in md


def test_to_json_round_trips_findings_and_score():
    findings = [Finding(tool="dns", severity="medium", title="No SPF", detail="d", recommendation="r")]
    report = make_report(findings)
    payload = json.loads(to_json(report))
    assert payload["target"] == "example.com"
    assert payload["score"] == report.score
    assert payload["findings"][0]["title"] == "No SPF"
    assert payload["tool_results"][0]["tool"] == "dns"
