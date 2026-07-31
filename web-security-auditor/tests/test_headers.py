from webauditor.fetcher import FetchResult
from webauditor.headers import evaluate_headers
from webauditor.models import Status


def make_response(headers, url="https://example.com/", final_url=None, status=200):
    return FetchResult(
        url=url,
        final_url=final_url or url,
        status=status,
        headers=list(headers.items()) if isinstance(headers, dict) else headers,
    )


def finding(findings, check_id):
    return next(f for f in findings if f.check_id == check_id)


def test_all_checks_pass_with_hardened_headers():
    response = make_response({
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
        "Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict",
    })
    findings = evaluate_headers(response)
    assert all(f.status == Status.PASS for f in findings), [f.to_dict() for f in findings]


def test_missing_headers_all_fail():
    response = make_response({})
    findings = evaluate_headers(response)
    statuses = {f.check_id: f.status for f in findings}
    assert statuses["hsts"] == Status.FAIL
    assert statuses["csp"] == Status.FAIL
    assert statuses["x-content-type-options"] == Status.FAIL
    assert statuses["frame-protection"] == Status.FAIL
    assert statuses["referrer-policy"] == Status.FAIL
    assert statuses["permissions-policy"] == Status.WARN
    assert statuses["server-disclosure"] == Status.PASS
    assert statuses["cookie-flags"] == Status.PASS


def test_hsts_short_max_age_warns():
    response = make_response({"Strict-Transport-Security": "max-age=60"})
    findings = evaluate_headers(response)
    assert finding(findings, "hsts").status == Status.WARN


def test_hsts_over_plain_http_is_not_a_fail():
    response = make_response({}, url="http://example.com/", final_url="http://example.com/")
    findings = evaluate_headers(response)
    hsts = finding(findings, "hsts")
    assert hsts.status == Status.WARN
    assert "plain HTTP" in hsts.message


def test_csp_with_unsafe_inline_warns():
    response = make_response({"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"})
    findings = evaluate_headers(response)
    csp = finding(findings, "csp")
    assert csp.status == Status.WARN
    assert "unsafe-inline" in csp.message


def test_frame_protection_passes_via_csp_frame_ancestors():
    response = make_response({"Content-Security-Policy": "frame-ancestors 'none'"})
    findings = evaluate_headers(response)
    assert finding(findings, "frame-protection").status == Status.PASS


def test_referrer_policy_unsafe_url_warns():
    response = make_response({"Referrer-Policy": "unsafe-url"})
    findings = evaluate_headers(response)
    assert finding(findings, "referrer-policy").status == Status.WARN


def test_server_header_with_version_warns():
    response = make_response({"Server": "nginx/1.18.0"})
    findings = evaluate_headers(response)
    server = finding(findings, "server-disclosure")
    assert server.status == Status.WARN
    assert "nginx/1.18.0" in server.message


def test_server_header_without_version_passes():
    response = make_response({"Server": "nginx"})
    findings = evaluate_headers(response)
    assert finding(findings, "server-disclosure").status == Status.PASS


def test_cookie_missing_flags_fails():
    response = make_response({"Set-Cookie": "session=abc123; Path=/"})
    findings = evaluate_headers(response)
    cookie = finding(findings, "cookie-flags")
    assert cookie.status == Status.FAIL
    assert "Secure" in cookie.message and "HttpOnly" in cookie.message and "SameSite" in cookie.message


def test_multiple_set_cookie_headers_are_all_evaluated():
    response = make_response([
        ("Set-Cookie", "good=1; Secure; HttpOnly; SameSite=Strict"),
        ("Set-Cookie", "bad=2; Path=/"),
    ])
    findings = evaluate_headers(response)
    cookie = finding(findings, "cookie-flags")
    assert cookie.status == Status.FAIL
    assert "bad" in cookie.message
    assert "good" not in cookie.message
