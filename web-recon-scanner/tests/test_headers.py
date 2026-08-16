from webrecon.headers import analyze_cookies, analyze_headers


def _by_header(findings, name):
    return next(f for f in findings if f.header == name)


def test_missing_hsts_flagged_high():
    findings = analyze_headers({})
    hsts = _by_header(findings, "Strict-Transport-Security")
    assert hsts.severity == "high"
    assert hsts.present is False


def test_hsts_present_with_short_max_age_flagged_medium():
    findings = analyze_headers({"Strict-Transport-Security": "max-age=60"})
    hsts = _by_header(findings, "Strict-Transport-Security")
    assert hsts.severity == "medium"
    assert "short" in hsts.message


def test_hsts_present_with_long_max_age_is_info():
    findings = analyze_headers({"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})
    hsts = _by_header(findings, "Strict-Transport-Security")
    assert hsts.severity == "info"


def test_csp_unsafe_inline_flagged():
    findings = analyze_headers({"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
    csp = _by_header(findings, "Content-Security-Policy")
    assert csp.severity == "medium"
    assert "unsafe-inline" in csp.message


def test_x_content_type_options_wrong_value_flagged():
    findings = analyze_headers({"X-Content-Type-Options": "sniff"})
    finding = _by_header(findings, "X-Content-Type-Options")
    assert finding.severity == "medium"


def test_x_frame_options_valid_value_is_info():
    findings = analyze_headers({"X-Frame-Options": "DENY"})
    finding = _by_header(findings, "X-Frame-Options")
    assert finding.severity == "info"


def test_header_lookup_is_case_insensitive():
    findings = analyze_headers({"x-frame-options": "SAMEORIGIN"})
    finding = _by_header(findings, "X-Frame-Options")
    assert finding.present is True
    assert finding.severity == "info"


def test_server_header_flagged_as_info_disclosure():
    findings = analyze_headers({"Server": "Apache/2.4.41 (Ubuntu)"})
    server_findings = [f for f in findings if f.header == "Server"]
    assert len(server_findings) == 1
    assert server_findings[0].severity == "low"


def test_no_info_disclosure_finding_when_headers_absent():
    findings = analyze_headers({"Strict-Transport-Security": "max-age=31536000"})
    assert not any(f.header in ("Server", "X-Powered-By") for f in findings)


def test_analyze_cookies_flags_missing_flags():
    findings = analyze_cookies(["session=abc123; Path=/"])
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "Secure" in findings[0].message
    assert "HttpOnly" in findings[0].message
    assert "SameSite" in findings[0].message


def test_analyze_cookies_all_flags_present_is_info():
    findings = analyze_cookies(["session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/"])
    assert findings[0].severity == "info"


def test_analyze_cookies_empty_list_returns_no_findings():
    assert analyze_cookies([]) == []
    assert analyze_cookies(None) == []
