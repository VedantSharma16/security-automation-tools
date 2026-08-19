import json

from webrecon.report import to_json, to_markdown

SAMPLE_RESULT = {
    "target": "https://example.test",
    "generated_at": "2026-08-19T00:00:00+00:00",
    "http": {"status_code": 200, "elapsed_ms": 42.0, "error": None},
    "security_headers": {
        "score": 60,
        "grade": "C",
        "findings": [{"header": "content-security-policy", "severity": "medium", "message": "Missing 'content-security-policy' header -- mitigates XSS."}],
    },
    "tls": {
        "host": "example.test", "protocol_version": "TLSv1.2", "subject": "CN=example.test",
        "issuer": "CN=Test CA", "not_after": "Dec 01 00:00:00 2026 GMT", "days_until_expiry": 104, "error": None,
    },
    "tls_findings": [],
    "technologies": [{"name": "nginx", "category": "web-server", "evidence": "nginx/1.18.0"}],
    "risk_score": 90,
    "risk_grade": "A",
    "narrative": "Overall posture is solid.",
}

UNREACHABLE_RESULT = {
    "target": "https://down.test",
    "generated_at": "2026-08-19T00:00:00+00:00",
    "http": {"status_code": 0, "elapsed_ms": 0.0, "error": "connection refused"},
    "security_headers": None,
    "tls": None,
    "tls_findings": [],
    "technologies": [],
    "risk_score": None,
    "risk_grade": None,
    "narrative": None,
}


def test_to_json_round_trips():
    parsed = json.loads(to_json(SAMPLE_RESULT))
    assert parsed["target"] == "https://example.test"
    assert parsed["risk_score"] == 90


def test_to_markdown_includes_key_sections():
    md = to_markdown(SAMPLE_RESULT)
    assert "# Web Recon Report: https://example.test" in md
    assert "## Risk Summary" in md
    assert "## Security Header Findings" in md
    assert "## TLS" in md
    assert "## Fingerprinted Technologies" in md
    assert "nginx" in md
    assert "Overall posture is solid." in md


def test_to_markdown_handles_unreachable_target():
    md = to_markdown(UNREACHABLE_RESULT)
    assert "**Target unreachable:** connection refused" in md
    assert "## Risk Summary" not in md
