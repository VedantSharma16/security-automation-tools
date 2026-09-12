from webrecon.fetcher import FetchResult
from webrecon.headers import (
    analyze_headers,
    check_banner_disclosure,
    check_content_type_options,
    check_cookies,
    check_csp,
    check_frame_protection,
    check_hsts,
    check_permissions_policy,
)


def _ids(findings):
    return {f.id for f in findings}


def test_missing_hsts_flagged_on_https_only():
    assert "missing-hsts" in _ids(check_hsts({}, "https"))
    assert check_hsts({}, "http") == []


def test_hsts_max_age_zero_flagged():
    findings = check_hsts({"Strict-Transport-Security": "max-age=0"}, "https")
    assert "hsts-max-age-zero" in _ids(findings)


def test_hsts_present_is_clean():
    findings = check_hsts({"Strict-Transport-Security": "max-age=31536000"}, "https")
    assert findings == []


def test_missing_csp_flagged():
    assert "missing-csp" in _ids(check_csp({}))


def test_csp_unsafe_inline_script_flagged():
    findings = check_csp({"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"})
    assert "csp-unsafe-inline-script" in _ids(findings)


def test_csp_strict_is_clean():
    findings = check_csp({"Content-Security-Policy": "default-src 'self'; script-src 'self'"})
    assert findings == []


def test_missing_clickjacking_protection():
    assert "missing-clickjacking-protection" in _ids(check_frame_protection({}))


def test_xfo_satisfies_clickjacking_protection():
    assert check_frame_protection({"X-Frame-Options": "DENY"}) == []


def test_csp_frame_ancestors_satisfies_clickjacking_protection():
    headers = {"Content-Security-Policy": "frame-ancestors 'none'"}
    assert check_frame_protection(headers) == []


def test_missing_nosniff_flagged():
    assert "missing-nosniff" in _ids(check_content_type_options({}))
    assert check_content_type_options({"X-Content-Type-Options": "nosniff"}) == []


def test_missing_permissions_policy_is_informational():
    findings = check_permissions_policy({})
    assert findings[0].severity == "info"


def test_banner_disclosure_flags_version_number():
    findings = check_banner_disclosure({"Server": "nginx/1.18.0"})
    assert "banner-disclosure-server" in _ids(findings)


def test_banner_without_version_not_flagged():
    # A generic value with no digits gives an attacker nothing to match a CVE against.
    assert check_banner_disclosure({"Server": "nginx"}) == []


def test_cookie_missing_all_flags_on_https():
    findings = check_cookies({"Set-Cookie": "session=abc123; Path=/"}, "https")
    assert len(findings) == 1
    assert "Secure" in findings[0].title
    assert "HttpOnly" in findings[0].title


def test_cookie_with_all_flags_is_clean():
    cookie = "session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"
    assert check_cookies({"Set-Cookie": cookie}, "https") == []


def test_multiple_folded_cookies_each_evaluated():
    raw = "a=1; HttpOnly, b=2; Secure; HttpOnly; SameSite=Lax"
    findings = check_cookies({"Set-Cookie": raw}, "https")
    ids = _ids(findings)
    assert "cookie-missing-flags-a" in ids
    assert "cookie-missing-flags-b" not in ids


def test_analyze_headers_skips_failed_fetch():
    failed = FetchResult(url="http://x", ok=False, error="boom")
    assert analyze_headers(failed, "http") == []


def test_analyze_headers_aggregates_multiple_findings():
    result = FetchResult(
        url="https://example.com",
        ok=True,
        status_code=200,
        headers={"Server": "Apache/2.4.1"},
        body="",
    )
    findings = analyze_headers(result, "https")
    ids = _ids(findings)
    assert "missing-hsts" in ids
    assert "missing-csp" in ids
    assert "missing-clickjacking-protection" in ids
    assert "missing-nosniff" in ids
    assert "banner-disclosure-server" in ids
