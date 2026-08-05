from websecaudit.cookies import analyze_cookies


def ids(findings):
    return {f.id for f in findings}


def test_fully_hardened_cookie_no_findings():
    findings = analyze_cookies(["session=abc; Secure; HttpOnly; SameSite=Strict"], "https")
    assert findings == []


def test_missing_secure_on_https_flagged_high():
    findings = analyze_cookies(["session=abc; HttpOnly; SameSite=Strict"], "https")
    matches = [f for f in findings if f.id == "cookie-missing-secure"]
    assert len(matches) == 1
    assert matches[0].severity == "high"


def test_secure_not_required_on_plain_http():
    findings = analyze_cookies(["session=abc; HttpOnly; SameSite=Strict"], "http")
    assert "cookie-missing-secure" not in ids(findings)


def test_missing_httponly_flagged():
    findings = analyze_cookies(["session=abc; Secure; SameSite=Strict"], "https")
    assert "cookie-missing-httponly" in ids(findings)


def test_missing_samesite_flagged():
    findings = analyze_cookies(["session=abc; Secure; HttpOnly"], "https")
    assert "cookie-missing-samesite" in ids(findings)


def test_samesite_none_without_secure_flagged_high():
    findings = analyze_cookies(["session=abc; HttpOnly; SameSite=None"], "https")
    matches = [f for f in findings if f.id == "cookie-samesite-none-without-secure"]
    assert len(matches) == 1
    assert matches[0].severity == "high"


def test_samesite_none_with_secure_not_flagged():
    findings = analyze_cookies(["session=abc; Secure; HttpOnly; SameSite=None"], "https")
    assert "cookie-samesite-none-without-secure" not in ids(findings)


def test_multiple_cookies_each_analyzed():
    findings = analyze_cookies(
        ["a=1; Secure; HttpOnly; SameSite=Strict", "b=2"], "https"
    )
    # the well-formed cookie "a" should contribute nothing; only "b" should
    assert len(findings) == 3  # missing secure, httponly, samesite for cookie "b"
    assert all("'b'" in f.message for f in findings)


def test_no_cookies_no_findings():
    assert analyze_cookies([], "https") == []
