from httpsec.cookies import analyze_cookies


def _ids(findings):
    return {f.id for f in findings}


def test_fully_flagged_cookie_has_no_findings():
    cookies = ["sessionid=abc123; Secure; HttpOnly; SameSite=Strict"]
    assert analyze_cookies(cookies, scheme="https") == []


def test_missing_secure_on_https():
    findings = analyze_cookies(["sessionid=abc; HttpOnly; SameSite=Strict"], scheme="https")
    assert "cookie-missing-secure" in _ids(findings)


def test_missing_secure_not_flagged_on_http():
    findings = analyze_cookies(["id=abc; HttpOnly; SameSite=Strict"], scheme="http")
    assert "cookie-missing-secure" not in _ids(findings)


def test_missing_httponly():
    findings = analyze_cookies(["sessionid=abc; Secure; SameSite=Strict"], scheme="https")
    assert "cookie-missing-httponly" in _ids(findings)


def test_missing_samesite():
    findings = analyze_cookies(["sessionid=abc; Secure; HttpOnly"], scheme="https")
    assert "cookie-missing-samesite" in _ids(findings)


def test_samesite_none_without_secure():
    findings = analyze_cookies(["id=abc; HttpOnly; SameSite=None"], scheme="https")
    assert "cookie-samesite-none-without-secure" in _ids(findings)


def test_samesite_none_with_secure_not_flagged_for_that_rule():
    findings = analyze_cookies(["id=abc; HttpOnly; SameSite=None; Secure"], scheme="https")
    assert "cookie-samesite-none-without-secure" not in _ids(findings)


def test_sensitive_cookie_name_raises_severity():
    sensitive = analyze_cookies(["auth_token=abc; SameSite=Strict"], scheme="https")
    non_sensitive = analyze_cookies(["visitor_id=abc; SameSite=Strict"], scheme="https")

    sensitive_secure = next(f for f in sensitive if f.id == "cookie-missing-secure")
    non_sensitive_secure = next(f for f in non_sensitive if f.id == "cookie-missing-secure")

    assert sensitive_secure.severity == "high"
    assert non_sensitive_secure.severity == "medium"


def test_multiple_cookies_each_analyzed_independently():
    findings = analyze_cookies(
        [
            "sessionid=abc; Secure; HttpOnly; SameSite=Strict",
            "tracking=xyz",
        ],
        scheme="https",
    )
    # only the second, unflagged cookie should produce findings
    assert all("tracking" in f.evidence for f in findings)
    assert len(findings) == 3  # secure, httponly, samesite all missing


def test_empty_list_returns_no_findings():
    assert analyze_cookies([], scheme="https") == []
