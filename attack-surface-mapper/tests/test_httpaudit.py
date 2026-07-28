from contextlib import contextmanager

from attack_surface_mapper import httpaudit


class _FakeResponse:
    def __init__(self, status, headers):
        self.status = status
        self.headers = headers


def _fake_opener(status, headers):
    @contextmanager
    def opener(request, timeout):
        yield _FakeResponse(status, headers)

    return opener


def test_fetch_headers_success():
    opener = _fake_opener(200, {"Server": "nginx"})
    status, headers = httpaudit.fetch_headers("https://example.com/", opener=opener)
    assert status == 200
    assert headers == {"server": "nginx"}


def test_fetch_headers_network_failure_returns_none():
    def opener(request, timeout):
        raise OSError("connection refused")

    status, headers = httpaudit.fetch_headers("https://example.com/", opener=opener)
    assert status is None
    assert headers == {}


def test_audit_headers_flags_missing_hsts_on_https():
    findings = httpaudit.audit_headers({}, scheme="https")
    titles = [f.title for f in findings]
    assert "Missing Strict-Transport-Security" in titles


def test_audit_headers_no_hsts_finding_on_plain_http():
    findings = httpaudit.audit_headers({}, scheme="http")
    titles = [f.title for f in findings]
    assert "Missing Strict-Transport-Security" not in titles


def test_audit_headers_clickjacking_satisfied_by_frame_ancestors_csp():
    headers = {"content-security-policy": "frame-ancestors 'self'"}
    findings = httpaudit.audit_headers(headers, scheme="https")
    titles = [f.title for f in findings]
    assert "Missing clickjacking protection" not in titles
    # CSP is present, so the generic "missing CSP" finding shouldn't fire either.
    assert "Missing content-security-policy" not in titles


def test_audit_headers_fully_hardened_response_has_no_findings():
    headers = {
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }
    assert httpaudit.audit_headers(headers, scheme="https") == []


def test_audit_banner_flags_version_disclosure():
    findings = httpaudit.audit_banner({"Server": "Apache/2.4.41 (Ubuntu)"})
    assert len(findings) == 1
    assert "Apache/2.4.41" in findings[0].detail


def test_audit_banner_ignores_generic_server_header():
    findings = httpaudit.audit_banner({"Server": "cloudflare"})
    assert findings == []


def test_audit_banner_no_headers():
    assert httpaudit.audit_banner({}) == []
