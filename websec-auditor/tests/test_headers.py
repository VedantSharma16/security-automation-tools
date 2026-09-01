from websec_auditor.headers import analyze_headers


def find(findings, finding_id):
    return next((f for f in findings if f.id == finding_id), None)


def test_flags_all_missing_headers_on_bare_https_response():
    headers = [("Content-Type", "text/html")]
    findings = analyze_headers(headers, is_https=True)
    ids = {f.id for f in findings}
    assert "missing-csp" in ids
    assert "missing-hsts" in ids
    assert "missing-xcto" in ids
    assert "missing-clickjacking-protection" in ids
    assert "missing-referrer-policy" in ids
    assert "missing-permissions-policy" in ids


def test_hsts_not_required_over_plain_http():
    headers = [("Content-Type", "text/html")]
    findings = analyze_headers(headers, is_https=False)
    assert find(findings, "missing-hsts") is None


def test_good_headers_produce_no_medium_or_higher_findings():
    headers = [
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "geolocation=()"),
    ]
    findings = analyze_headers(headers, is_https=True)
    assert not any(f.severity in ("medium", "high", "critical") for f in findings)


def test_weak_csp_unsafe_inline_flagged():
    headers = [("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")]
    findings = analyze_headers(headers, is_https=False)
    assert find(findings, "weak-csp") is not None


def test_hsts_short_max_age_flagged():
    headers = [("Strict-Transport-Security", "max-age=60")]
    findings = analyze_headers(headers, is_https=True)
    assert find(findings, "weak-hsts-max-age") is not None


def test_x_frame_options_satisfies_clickjacking_check():
    headers = [("X-Frame-Options", "DENY")]
    findings = analyze_headers(headers, is_https=False)
    assert find(findings, "missing-clickjacking-protection") is None


def test_csp_frame_ancestors_satisfies_clickjacking_check():
    headers = [("Content-Security-Policy", "frame-ancestors 'self'")]
    findings = analyze_headers(headers, is_https=False)
    assert find(findings, "missing-clickjacking-protection") is None


def test_server_header_version_disclosure():
    headers = [("Server", "Apache/2.4.41 (Ubuntu)")]
    findings = analyze_headers(headers, is_https=False)
    assert find(findings, "version-disclosure-server") is not None


def test_server_header_without_version_not_flagged():
    headers = [("Server", "nginx")]
    findings = analyze_headers(headers, is_https=False)
    assert find(findings, "version-disclosure-server") is None


def test_cookie_missing_secure_and_httponly_over_https():
    headers = [("Set-Cookie", "session=abc123; Path=/")]
    findings = analyze_headers(headers, is_https=True)
    assert find(findings, "cookie-missing-secure") is not None
    assert find(findings, "cookie-missing-httponly") is not None
    assert find(findings, "cookie-missing-samesite") is not None


def test_cookie_secure_httponly_samesite_lax_is_clean():
    headers = [("Set-Cookie", "session=abc123; Secure; HttpOnly; SameSite=Lax; Path=/")]
    findings = analyze_headers(headers, is_https=True)
    cookie_findings = [f for f in findings if f.category == "cookies"]
    assert cookie_findings == []


def test_multiple_set_cookie_headers_are_each_analyzed():
    headers = [
        ("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Lax"),
        ("Set-Cookie", "b=2; Path=/"),  # missing everything
    ]
    findings = analyze_headers(headers, is_https=True)
    b_findings = [f for f in findings if f.evidence.get("cookie") == "b"]
    assert len(b_findings) == 3  # secure, httponly, samesite
    a_findings = [f for f in findings if f.evidence.get("cookie") == "a"]
    assert a_findings == []


def test_samesite_none_without_secure_is_high_severity():
    headers = [("Set-Cookie", "a=1; SameSite=None")]
    findings = analyze_headers(headers, is_https=True)
    finding = find(findings, "cookie-samesite-none-without-secure")
    assert finding is not None
    assert finding.severity == "high"
