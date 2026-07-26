from __future__ import annotations

from requests.structures import CaseInsensitiveDict

from websec.checks.fingerprint import fingerprint


def test_fingerprints_server_header():
    headers = CaseInsensitiveDict({"Server": "nginx/1.25.0"})
    findings = fingerprint("http://x/", headers, "<html></html>")
    assert len(findings) == 1
    assert "nginx/1.25.0" in findings[0].detail


def test_fingerprints_generator_meta_tag():
    html = '<html><head><meta name="generator" content="WordPress 6.4"></head></html>'
    findings = fingerprint("http://x/", CaseInsensitiveDict(), html)
    assert "WordPress 6.4" in findings[0].detail


def test_fingerprints_content_signature():
    html = "<html><body><img src='/wp-content/uploads/x.png'></body></html>"
    findings = fingerprint("http://x/", CaseInsensitiveDict(), html)
    assert "WordPress" in findings[0].detail


def test_no_findings_when_nothing_detected():
    findings = fingerprint("http://x/", CaseInsensitiveDict(), "<html></html>")
    assert findings == []
