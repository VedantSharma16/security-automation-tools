import json

from websec_auditor.audit import AuditResult
from websec_auditor.findings import Finding
from websec_auditor.report import render_json, render_markdown


def sample_result(findings=None, fetch_error=None):
    return AuditResult(
        url="https://example.com/",
        final_url="https://example.com/",
        status=200,
        is_https=True,
        findings=findings or [],
        technologies=["nginx"],
        score=100,
        grade="A",
        well_known={"robots.txt": 200},
        fetch_error=fetch_error,
    )


def test_render_json_round_trips_via_to_dict():
    result = sample_result([Finding(id="x", severity="low", category="headers", message="m")])
    parsed = json.loads(render_json(result))
    assert parsed["grade"] == "A"
    assert parsed["findings"][0]["id"] == "x"
    assert parsed["technologies"] == ["nginx"]


def test_render_markdown_includes_grade_and_url():
    result = sample_result()
    md = render_markdown(result)
    assert "https://example.com/" in md
    assert "Grade:** A" in md


def test_render_markdown_no_issues_message_when_clean():
    md = render_markdown(sample_result())
    assert "No issues found." in md


def test_render_markdown_orders_findings_most_severe_first():
    findings = [
        Finding(id="low1", severity="low", category="headers", message="low issue"),
        Finding(id="crit1", severity="critical", category="tls", message="critical issue"),
        Finding(id="med1", severity="medium", category="headers", message="medium issue"),
    ]
    md = render_markdown(sample_result(findings))
    assert md.index("critical issue") < md.index("medium issue") < md.index("low issue")


def test_render_markdown_reports_fetch_error():
    md = render_markdown(sample_result(fetch_error="timed out"))
    assert "timed out" in md
