from httpsec.headers import analyze_headers


def _ids(findings):
    return {f.id for f in findings}


def test_fully_hardened_response_has_no_findings():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    assert analyze_headers(headers, scheme="https") == []


def test_missing_hsts_on_https():
    findings = analyze_headers({}, scheme="https")
    assert "header-missing-hsts" in _ids(findings)


def test_missing_hsts_not_flagged_on_plain_http():
    findings = analyze_headers({}, scheme="http")
    assert "header-missing-hsts" not in _ids(findings)


def test_weak_hsts_max_age_and_no_subdomains():
    findings = analyze_headers({"Strict-Transport-Security": "max-age=60"}, scheme="https")
    ids = _ids(findings)
    assert "header-weak-hsts-max-age" in ids
    assert "header-hsts-no-subdomains" in ids


def test_csp_unsafe_inline_and_eval_and_wildcard():
    findings = analyze_headers(
        {"Content-Security-Policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'"},
        scheme="https",
    )
    ids = _ids(findings)
    assert "header-csp-unsafe-inline" in ids
    assert "header-csp-unsafe-eval" in ids
    assert "header-csp-wildcard-source" in ids


def test_missing_csp_flagged():
    findings = analyze_headers({}, scheme="https")
    assert "header-missing-csp" in _ids(findings)


def test_clickjacking_protection_via_csp_frame_ancestors_suppresses_xfo_finding():
    findings = analyze_headers(
        {"Content-Security-Policy": "frame-ancestors 'self'"}, scheme="https"
    )
    assert "header-missing-clickjacking-protection" not in _ids(findings)


def test_missing_clickjacking_protection():
    findings = analyze_headers({}, scheme="https")
    assert "header-missing-clickjacking-protection" in _ids(findings)


def test_case_insensitive_header_lookup():
    findings = analyze_headers({"x-content-type-options": "nosniff"}, scheme="https")
    assert "header-missing-xcto" not in _ids(findings)


def test_invalid_xcto_value_flagged():
    findings = analyze_headers({"X-Content-Type-Options": "sniff-away"}, scheme="https")
    assert "header-missing-xcto" in _ids(findings)


def test_unsafe_url_referrer_policy_flagged():
    findings = analyze_headers({"Referrer-Policy": "unsafe-url"}, scheme="https")
    assert "header-unsafe-referrer-policy" in _ids(findings)


def test_server_header_info_disclosure():
    findings = analyze_headers({"Server": "Apache/2.4.49 (Unix)"}, scheme="https")
    matches = [f for f in findings if f.id == "header-info-disclosure-server"]
    assert len(matches) == 1
    assert matches[0].severity == "info"
    assert "2.4.49" in matches[0].evidence


def test_x_powered_by_disclosure():
    findings = analyze_headers({"X-Powered-By": "PHP/7.2.0"}, scheme="https")
    assert "header-info-disclosure-x-powered-by" in _ids(findings)
