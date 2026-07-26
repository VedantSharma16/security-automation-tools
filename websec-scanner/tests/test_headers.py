from __future__ import annotations

from requests.structures import CaseInsensitiveDict

from websec.checks.headers import check_headers
from websec.models import Severity


def test_flags_missing_headers_on_http():
    headers = CaseInsensitiveDict({"Server": "Werkzeug/3.1 Python/3.11"})
    findings = check_headers("http://example.test/", headers, is_https=False)
    titles = {f.title for f in findings}
    assert "Missing Content-Security-Policy header" in titles
    assert "Missing clickjacking protection" in titles
    # HSTS only applies to HTTPS targets.
    assert not any("Strict-Transport-Security" in t for t in titles)
    server_findings = [f for f in findings if "Server header" in f.title]
    assert server_findings and server_findings[0].severity == Severity.LOW


def test_flags_missing_hsts_on_https():
    findings = check_headers("https://example.test/", CaseInsensitiveDict(), is_https=True)
    assert any("Strict-Transport-Security" in f.title for f in findings)


def test_csp_frame_ancestors_satisfies_frame_protection():
    headers = CaseInsensitiveDict(
        {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        }
    )
    findings = check_headers("http://example.test/", headers, is_https=False)
    assert not any("clickjacking" in f.title for f in findings)


def test_fully_configured_response_has_no_findings():
    headers = CaseInsensitiveDict(
        {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Strict-Transport-Security": "max-age=63072000",
        }
    )
    findings = check_headers("https://example.test/", headers, is_https=True)
    assert findings == []
