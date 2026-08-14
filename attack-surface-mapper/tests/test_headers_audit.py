from __future__ import annotations

from asmapper.headers_audit import audit_headers
from asmapper.models import Severity


def test_no_headers_flags_all_missing_security_headers():
    findings = audit_headers({})
    ids = {f.id for f in findings}
    assert "header-missing-content-security-policy" in ids
    assert "header-missing-strict-transport-security" in ids
    assert "header-missing-x-frame-options" in ids


def test_csp_with_frame_ancestors_suppresses_x_frame_options_finding():
    headers = {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}
    findings = audit_headers(headers)
    ids = {f.id for f in findings}
    assert "header-missing-x-frame-options" not in ids
    assert "header-missing-content-security-policy" not in ids


def test_full_good_headers_produce_no_missing_header_findings():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    findings = audit_headers(headers)
    assert findings == []


def test_server_header_with_version_flags_disclosure():
    findings = audit_headers({"Server": "Apache/2.4.41 (Ubuntu)"})
    disclosure = [f for f in findings if f.id == "header-version-disclosure-server"]
    assert len(disclosure) == 1
    assert disclosure[0].severity == Severity.LOW


def test_server_header_without_version_does_not_flag_disclosure():
    findings = audit_headers({"Server": "nginx"})
    ids = {f.id for f in findings}
    assert "header-version-disclosure-server" not in ids


def test_cookie_missing_all_flags():
    findings = audit_headers({"Set-Cookie": "session=abc123; Path=/"})
    ids = {f.id for f in findings}
    assert "cookie-missing-secure" in ids
    assert "cookie-missing-httponly" in ids
    assert "cookie-missing-samesite" in ids


def test_cookie_with_all_flags_set_is_clean():
    findings = audit_headers({"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict"})
    cookie_findings = [f for f in findings if f.category == "headers" and f.id.startswith("cookie-")]
    assert cookie_findings == []
