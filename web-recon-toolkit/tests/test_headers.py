from webrecon.headers import check_security_headers
from webrecon.models import Severity


def _ids(findings):
    return {f.id for f in findings}


def test_flags_all_missing_headers_on_bare_https_response():
    findings = check_security_headers({}, is_https=True)
    ids = _ids(findings)
    assert "header-missing-strict-transport-security" in ids
    assert "header-missing-content-security-policy" in ids
    assert "header-missing-x-content-type-options" in ids
    assert "header-missing-referrer-policy" in ids
    assert "header-missing-permissions-policy" in ids
    assert "header-missing-frame-protection" in ids


def test_hsts_only_checked_over_https():
    findings = check_security_headers({}, is_https=False)
    assert "header-missing-strict-transport-security" not in _ids(findings)


def test_fully_hardened_response_has_no_header_findings():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
        "X-Frame-Options": "DENY",
    }
    findings = check_security_headers(headers, is_https=True)
    assert findings == []


def test_csp_frame_ancestors_satisfies_clickjacking_check_without_xfo():
    headers = {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}
    findings = check_security_headers(headers, is_https=False)
    assert "header-missing-frame-protection" not in _ids(findings)


def test_server_header_flagged_as_disclosure():
    headers = {"Server": "Apache/2.4.29 (Ubuntu)"}
    findings = check_security_headers(headers, is_https=False)
    disclosure = [f for f in findings if f.id == "disclosure-server"]
    assert len(disclosure) == 1
    assert "Apache/2.4.29" in disclosure[0].evidence
    assert disclosure[0].severity == Severity.LOW


def test_cookie_missing_all_flags_is_medium_severity():
    findings = check_security_headers(
        {}, is_https=True, set_cookie_headers=["sessionid=abc123; Path=/"]
    )
    cookie_findings = [f for f in findings if f.category == "cookies"]
    assert len(cookie_findings) == 1
    assert cookie_findings[0].severity == Severity.MEDIUM
    assert "Secure" in cookie_findings[0].title
    assert "HttpOnly" in cookie_findings[0].title
    assert "SameSite" in cookie_findings[0].title


def test_cookie_with_all_flags_is_not_flagged():
    findings = check_security_headers(
        {},
        is_https=True,
        set_cookie_headers=["sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"],
    )
    assert [f for f in findings if f.category == "cookies"] == []


def test_multiple_cookies_each_evaluated_independently():
    findings = check_security_headers(
        {},
        is_https=True,
        set_cookie_headers=[
            "sessionid=abc; Secure; HttpOnly; SameSite=Strict",
            "tracking=xyz; Path=/",
        ],
    )
    cookie_findings = [f for f in findings if f.category == "cookies"]
    assert len(cookie_findings) == 1
    assert "tracking" in cookie_findings[0].title
