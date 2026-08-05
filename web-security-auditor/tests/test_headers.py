from websecaudit.headers import analyze_headers

GOOD_HTTPS_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
}


def ids(findings):
    return {f.id for f in findings}


def test_fully_hardened_site_has_no_findings():
    findings = analyze_headers(GOOD_HTTPS_HEADERS, "https", [])
    assert findings == []


def test_missing_hsts_on_https():
    headers = dict(GOOD_HTTPS_HEADERS)
    del headers["strict-transport-security"]
    findings = analyze_headers(headers, "https", [])
    assert "missing-hsts" in ids(findings)


def test_weak_hsts_max_age():
    headers = dict(GOOD_HTTPS_HEADERS, **{"strict-transport-security": "max-age=100; includeSubDomains"})
    findings = analyze_headers(headers, "https", [])
    assert "weak-hsts-max-age" in ids(findings)


def test_hsts_missing_includesubdomains_is_info_level():
    headers = dict(GOOD_HTTPS_HEADERS, **{"strict-transport-security": "max-age=31536000"})
    findings = analyze_headers(headers, "https", [])
    matches = [f for f in findings if f.id == "hsts-missing-includesubdomains"]
    assert len(matches) == 1
    assert matches[0].severity == "info"


def test_plaintext_http_without_upgrade_flagged_high():
    findings = analyze_headers({}, "http", [])
    matches = [f for f in findings if f.id == "plaintext-http"]
    assert len(matches) == 1
    assert matches[0].severity == "high"


def test_http_redirected_to_https_not_flagged():
    findings = analyze_headers({}, "http", [("https://example.com/", 301)])
    assert "plaintext-http" not in ids(findings)


def test_missing_csp():
    headers = dict(GOOD_HTTPS_HEADERS)
    del headers["content-security-policy"]
    findings = analyze_headers(headers, "https", [])
    assert "missing-csp" in ids(findings)


def test_csp_unsafe_inline_flagged():
    headers = dict(GOOD_HTTPS_HEADERS, **{"content-security-policy": "default-src 'self' 'unsafe-inline'"})
    findings = analyze_headers(headers, "https", [])
    assert "csp-unsafe-directives" in ids(findings)


def test_csp_missing_src_directive():
    headers = dict(GOOD_HTTPS_HEADERS, **{"content-security-policy": "object-src 'none'"})
    findings = analyze_headers(headers, "https", [])
    assert "csp-missing-src-directive" in ids(findings)


def test_missing_content_type_options():
    headers = dict(GOOD_HTTPS_HEADERS)
    del headers["x-content-type-options"]
    findings = analyze_headers(headers, "https", [])
    assert "missing-x-content-type-options" in ids(findings)


def test_missing_clickjacking_protection():
    headers = dict(GOOD_HTTPS_HEADERS)
    del headers["x-frame-options"]
    findings = analyze_headers(headers, "https", [])
    assert "missing-clickjacking-protection" in ids(findings)


def test_csp_frame_ancestors_satisfies_clickjacking_check():
    headers = dict(GOOD_HTTPS_HEADERS)
    del headers["x-frame-options"]
    headers["content-security-policy"] = "default-src 'self'; frame-ancestors 'none'"
    findings = analyze_headers(headers, "https", [])
    assert "missing-clickjacking-protection" not in ids(findings)


def test_missing_referrer_policy():
    headers = dict(GOOD_HTTPS_HEADERS)
    del headers["referrer-policy"]
    findings = analyze_headers(headers, "https", [])
    assert "missing-referrer-policy" in ids(findings)


def test_unsafe_url_referrer_policy_flagged():
    headers = dict(GOOD_HTTPS_HEADERS, **{"referrer-policy": "unsafe-url"})
    findings = analyze_headers(headers, "https", [])
    assert "permissive-referrer-policy" in ids(findings)


def test_missing_permissions_policy_is_info():
    headers = dict(GOOD_HTTPS_HEADERS)
    del headers["permissions-policy"]
    findings = analyze_headers(headers, "https", [])
    matches = [f for f in findings if f.id == "missing-permissions-policy"]
    assert len(matches) == 1
    assert matches[0].severity == "info"


def test_server_header_with_version_flagged():
    headers = dict(GOOD_HTTPS_HEADERS, **{"server": "nginx/1.18.0"})
    findings = analyze_headers(headers, "https", [])
    assert "server-header-discloses-version" in ids(findings)


def test_server_header_without_version_not_flagged():
    headers = dict(GOOD_HTTPS_HEADERS, **{"server": "nginx"})
    findings = analyze_headers(headers, "https", [])
    assert "server-header-discloses-version" not in ids(findings)


def test_x_powered_by_flagged():
    headers = dict(GOOD_HTTPS_HEADERS, **{"x-powered-by": "PHP/8.2"})
    findings = analyze_headers(headers, "https", [])
    assert "x-powered-by-disclosure" in ids(findings)
