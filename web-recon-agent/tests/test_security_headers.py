from recon_agent.security_headers import grade


def test_grade_flags_all_missing_headers_on_https():
    result = grade({}, scheme="https")
    missing_names = {item["header"] for item in result["missing"]}
    assert "Strict-Transport-Security" in missing_names
    assert "Content-Security-Policy" in missing_names
    assert result["score"] < 100


def test_hsts_not_required_over_plain_http():
    result = grade({}, scheme="http")
    missing_names = {item["header"] for item in result["missing"]}
    assert "Strict-Transport-Security" not in missing_names


def test_well_configured_headers_score_100():
    headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    result = grade(headers, scheme="https")
    assert result["score"] == 100
    assert result["missing"] == []


def test_case_insensitive_header_lookup():
    headers = {"x-content-type-options": "nosniff"}
    result = grade(headers, scheme="http")
    assert not any(item["header"] == "X-Content-Type-Options" for item in result["missing"])


def test_wrong_value_is_flagged_as_missing():
    headers = {"X-Content-Type-Options": "sniff-away"}
    result = grade(headers, scheme="http")
    assert any(item["header"] == "X-Content-Type-Options" for item in result["missing"])


def test_info_disclosure_headers_reported():
    headers = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"}
    result = grade(headers, scheme="http")
    disclosed = {item["header"] for item in result["info_disclosure"]}
    assert disclosed == {"server", "x-powered-by"}
