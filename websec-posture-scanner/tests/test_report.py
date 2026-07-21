import json

from webscan.models import Finding, ScanResult, TLSInfo
from webscan.report import render_json, render_markdown, render_text


def _result() -> ScanResult:
    findings = [
        Finding(
            id="headers-hsts-missing",
            title="Missing HSTS",
            severity="high",
            category="headers",
            description="No HSTS header.",
            remediation="Add it.",
            evidence="",
        ),
        Finding(
            id="cors-wildcard-origin",
            title="Wildcard CORS",
            severity="info",
            category="cors",
            description="CORS is wide open.",
            remediation="Restrict it.",
            evidence="Access-Control-Allow-Origin: *",
        ),
    ]
    tls = TLSInfo(
        hostname="example.com",
        port=443,
        protocol_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        not_after="Jan  1 00:00:00 2027 GMT",
        days_until_expiry=365,
    )
    return ScanResult(target_url="https://example.com/", findings=findings, score=85, grade="B", tls=tls)


def test_render_text_includes_key_facts():
    text = render_text(_result())
    assert "Grade: B" in text
    assert "score 85/100" in text
    assert "Missing HSTS" in text
    assert "HIGH" in text
    assert "TLSv1.3" in text


def test_render_text_no_findings():
    result = ScanResult(target_url="https://example.com/", findings=[], score=100, grade="A")
    assert "No findings." in render_text(result)


def test_render_markdown_has_table_and_sections():
    md = render_markdown(_result())
    assert md.startswith("# Web Security Posture Scan")
    assert "| Severity | Title | Category |" in md
    assert "### Missing HSTS" in md


def test_render_json_round_trips():
    result = _result()
    data = json.loads(render_json(result))
    assert data["grade"] == "B"
    assert data["score"] == 85
    assert len(data["findings"]) == 2
    assert data["findings"][0]["id"] == "headers-hsts-missing"
    assert data["tls"]["protocol_version"] == "TLSv1.3"


def test_findings_sorted_by_severity_in_report():
    text = render_text(_result())
    assert text.index("Missing HSTS") < text.index("Wildcard CORS")
