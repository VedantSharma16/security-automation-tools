from http_audit.fetcher import HttpResponse
from http_audit.headers import check_headers


def _response(headers: dict[str, str]) -> HttpResponse:
    return HttpResponse(url="https://example.com/", status=200, headers={k.lower(): v for k, v in headers.items()})


def test_missing_headers_all_flagged():
    findings = check_headers(_response({}))
    by_name = {f.name: f for f in findings}
    assert by_name["Strict-Transport-Security"].severity == "high"
    assert by_name["Content-Security-Policy"].severity == "high"
    assert by_name["X-Content-Type-Options"].severity == "low"
    assert by_name["Clickjacking protection"].severity == "medium"
    assert by_name["Referrer-Policy"].severity == "low"
    assert by_name["Permissions-Policy"].severity == "info"


def test_fully_hardened_headers_all_pass():
    findings = check_headers(
        _response(
            {
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            }
        )
    )
    assert all(f.severity == "pass" for f in findings), findings


def test_short_hsts_max_age_is_medium():
    findings = check_headers(_response({"Strict-Transport-Security": "max-age=100"}))
    hsts = next(f for f in findings if f.name == "Strict-Transport-Security")
    assert hsts.severity == "medium"


def test_unsafe_inline_csp_flagged():
    findings = check_headers(_response({"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}))
    csp = next(f for f in findings if f.name == "Content-Security-Policy")
    assert csp.severity == "medium"
    assert "unsafe-inline" in csp.message


def test_frame_ancestors_in_csp_satisfies_clickjacking_check():
    findings = check_headers(_response({"Content-Security-Policy": "frame-ancestors 'none'"}))
    clickjacking = next(f for f in findings if f.name == "Clickjacking protection")
    assert clickjacking.severity == "pass"


def test_server_header_with_version_flagged():
    findings = check_headers(_response({"Server": "nginx/1.18.0"}))
    disclosures = [f for f in findings if "disclosure" in f.name.lower()]
    assert len(disclosures) == 1
    assert disclosures[0].severity == "low"


def test_server_header_without_version_not_flagged():
    findings = check_headers(_response({"Server": "webserver"}))
    disclosures = [f for f in findings if "disclosure" in f.name.lower()]
    assert disclosures == []
