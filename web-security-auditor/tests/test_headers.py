from webaudit import headers


def test_hsts_not_applicable_on_http():
    result = headers.check_hsts({}, is_https=False)
    assert result.status == "info"


def test_hsts_missing_on_https_fails():
    result = headers.check_hsts({}, is_https=True)
    assert result.status == "fail"
    assert result.severity == "high"


def test_hsts_short_max_age_warns():
    result = headers.check_hsts({"strict-transport-security": "max-age=3600"}, is_https=True)
    assert result.status == "warn"


def test_hsts_strong_passes():
    result = headers.check_hsts(
        {"strict-transport-security": "max-age=31536000; includeSubDomains"}, is_https=True
    )
    assert result.status == "pass"


def test_csp_missing_fails():
    result = headers.check_csp({})
    assert result.status == "fail"


def test_csp_unsafe_inline_warns():
    result = headers.check_csp({"content-security-policy": "script-src 'unsafe-inline'"})
    assert result.status == "warn"


def test_csp_wildcard_source_warns():
    result = headers.check_csp({"content-security-policy": "default-src *"})
    assert result.status == "warn"


def test_csp_strict_passes():
    result = headers.check_csp({"content-security-policy": "default-src 'self'"})
    assert result.status == "pass"


def test_x_content_type_options_missing_fails():
    assert headers.check_x_content_type_options({}).status == "fail"


def test_x_content_type_options_present_passes():
    result = headers.check_x_content_type_options({"x-content-type-options": "nosniff"})
    assert result.status == "pass"


def test_frame_options_missing_fails():
    assert headers.check_frame_options({}).status == "fail"


def test_frame_options_deny_passes():
    result = headers.check_frame_options({"x-frame-options": "DENY"})
    assert result.status == "pass"


def test_frame_options_covered_by_csp_frame_ancestors():
    result = headers.check_frame_options({"content-security-policy": "frame-ancestors 'none'"})
    assert result.status == "pass"


def test_referrer_policy_missing_warns():
    assert headers.check_referrer_policy({}).status == "warn"


def test_referrer_policy_unsafe_url_warns():
    result = headers.check_referrer_policy({"referrer-policy": "unsafe-url"})
    assert result.status == "warn"


def test_referrer_policy_strict_passes():
    result = headers.check_referrer_policy({"referrer-policy": "strict-origin-when-cross-origin"})
    assert result.status == "pass"


def test_permissions_policy_missing_warns():
    assert headers.check_permissions_policy({}).status == "warn"


def test_run_all_returns_six_checks():
    results = headers.run_all({}, is_https=True)
    assert len(results) == 6
