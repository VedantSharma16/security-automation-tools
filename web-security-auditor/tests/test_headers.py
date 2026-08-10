from webauditor.findings import Severity
from webauditor.headers import analyze_cookies, analyze_security_headers

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}


def test_fully_hardened_response_has_no_findings():
    findings = analyze_security_headers(GOOD_HEADERS)
    assert findings == []


def test_missing_all_headers_flags_each_one():
    findings = analyze_security_headers({})
    ids = {f.id for f in findings}
    assert "HDR-HSTS-MISSING" in ids
    assert "HDR-CSP-MISSING" in ids
    assert "HDR-NOSNIFF-MISSING" in ids
    assert "HDR-REFERRER-MISSING" in ids
    assert "HDR-PERMISSIONS-MISSING" in ids
    assert "HDR-CLICKJACKING" in ids


def test_header_lookup_is_case_insensitive():
    headers = {k.lower(): v for k, v in GOOD_HEADERS.items()}
    findings = analyze_security_headers(headers)
    assert findings == []


def test_csp_frame_ancestors_satisfies_clickjacking_check():
    headers = dict(GOOD_HEADERS)
    findings = analyze_security_headers(headers)
    assert not any(f.id == "HDR-CLICKJACKING" for f in findings)


def test_x_frame_options_satisfies_clickjacking_check_without_csp():
    headers = {**GOOD_HEADERS, "X-Frame-Options": "DENY"}
    del headers["Content-Security-Policy"]
    findings = analyze_security_headers(headers)
    assert not any(f.id == "HDR-CLICKJACKING" for f in findings)
    assert any(f.id == "HDR-CSP-MISSING" for f in findings)


def test_server_banner_flagged_as_info_disclosure():
    headers = {**GOOD_HEADERS, "Server": "Apache/2.4.41 (Ubuntu)"}
    findings = analyze_security_headers(headers)
    disclosure = [f for f in findings if f.id == "HDR-INFO-DISCLOSURE-SERVER"]
    assert len(disclosure) == 1
    assert disclosure[0].severity == Severity.INFO
    assert "Apache/2.4.41" in disclosure[0].evidence


def test_cookie_with_all_flags_has_no_findings():
    findings = analyze_cookies(["session=abc123; Secure; HttpOnly; SameSite=Lax"])
    assert findings == []


def test_cookie_missing_secure_httponly_samesite_flags_all_three():
    findings = analyze_cookies(["session=abc123"])
    ids = {f.id for f in findings}
    assert ids == {"COOKIE-NO-SECURE", "COOKIE-NO-HTTPONLY", "COOKIE-NO-SAMESITE"}


def test_cookie_flag_matching_is_case_insensitive():
    findings = analyze_cookies(["session=abc123; secure; httponly; samesite=strict"])
    assert findings == []


def test_no_cookies_produces_no_findings():
    assert analyze_cookies([]) == []


def test_multiple_cookies_evaluated_independently():
    findings = analyze_cookies([
        "good=1; Secure; HttpOnly; SameSite=Strict",
        "bad=2",
    ])
    assert all("bad" in f.title for f in findings)
