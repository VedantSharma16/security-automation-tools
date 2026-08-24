from webauditor.fetch import FetchResult
from webauditor.headers import check_headers


def _result(headers=None, set_cookie=None) -> FetchResult:
    return FetchResult(
        url="https://example.com",
        status_code=200,
        headers=headers or {},
        set_cookie_headers=set_cookie or [],
        body="",
    )


def test_flags_missing_hsts_only_over_https():
    findings = check_headers(_result(headers={}), scheme="https")
    ids = {f.id for f in findings}
    assert "missing-hsts" in ids

    findings_http = check_headers(_result(headers={}), scheme="http")
    ids_http = {f.id for f in findings_http}
    assert "missing-hsts" not in ids_http


def test_no_findings_for_fully_hardened_response():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    findings = check_headers(_result(headers=headers), scheme="https")
    assert findings == []


def test_csp_with_unsafe_inline_flagged():
    headers = {"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"}
    findings = check_headers(_result(headers=headers), scheme="https")
    assert any(f.id == "weak-csp" for f in findings)


def test_csp_frame_ancestors_satisfies_clickjacking_check():
    headers = {"Content-Security-Policy": "frame-ancestors 'none'"}
    findings = check_headers(_result(headers=headers), scheme="https")
    assert not any(f.id == "missing-clickjacking-protection" for f in findings)


def test_server_header_with_version_flagged():
    headers = {"Server": "Apache/2.4.29 (Ubuntu)"}
    findings = check_headers(_result(headers=headers), scheme="https")
    assert any(f.id == "version-disclosure-server" for f in findings)


def test_server_header_without_version_not_flagged():
    headers = {"Server": "nginx"}
    findings = check_headers(_result(headers=headers), scheme="https")
    assert not any(f.id.startswith("version-disclosure") for f in findings)


def test_cookie_missing_secure_and_httponly_flagged_high():
    findings = check_headers(_result(set_cookie=["session=abc123; Path=/"]), scheme="https")
    matches = [f for f in findings if f.id == "cookie-missing-flags-session"]
    assert len(matches) == 1
    finding = matches[0]
    assert finding.severity.name == "HIGH"
    assert "Secure" in finding.title
    assert "HttpOnly" in finding.title


def test_cookie_missing_only_samesite_flagged_medium():
    findings = check_headers(
        _result(set_cookie=["session=abc123; Path=/; Secure; HttpOnly"]), scheme="https"
    )
    matches = [f for f in findings if f.id == "cookie-missing-flags-session"]
    assert len(matches) == 1
    assert matches[0].severity.name == "MEDIUM"
    assert matches[0].title.endswith("SameSite")


def test_fully_flagged_cookie_not_reported():
    findings = check_headers(
        _result(set_cookie=["session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"]),
        scheme="https",
    )
    assert not any(f.id.startswith("cookie-missing-flags") for f in findings)


def test_multiple_cookies_each_evaluated_independently():
    findings = check_headers(
        _result(
            set_cookie=[
                "a=1; Secure; HttpOnly; SameSite=Strict",
                "b=2; Path=/",
            ]
        ),
        scheme="https",
    )
    ids = {f.id for f in findings}
    assert "cookie-missing-flags-a" not in ids
    assert "cookie-missing-flags-b" in ids
