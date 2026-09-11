from webaudit import cookies


def test_fully_flagged_cookie_passes():
    results = cookies.analyze_cookies(
        ["session=abc123; Secure; HttpOnly; SameSite=Strict"], is_https=True
    )
    assert len(results) == 1
    assert results[0].status == "pass"
    assert results[0].id == "cookie:session"


def test_missing_secure_on_https_fails_high():
    results = cookies.analyze_cookies(["session=abc123; HttpOnly; SameSite=Strict"], is_https=True)
    assert results[0].status == "fail"
    assert results[0].severity == "high"
    assert "Secure" in results[0].detail


def test_missing_httponly_fails():
    results = cookies.analyze_cookies(["session=abc123; Secure; SameSite=Strict"], is_https=True)
    assert results[0].status == "fail"
    assert "HttpOnly" in results[0].detail


def test_missing_samesite_fails():
    results = cookies.analyze_cookies(["session=abc123; Secure; HttpOnly"], is_https=True)
    assert results[0].status == "fail"
    assert "SameSite" in results[0].detail


def test_samesite_none_without_secure_fails_high():
    results = cookies.analyze_cookies(
        ["session=abc123; HttpOnly; SameSite=None"], is_https=True
    )
    assert results[0].status == "fail"
    assert results[0].severity == "high"


def test_secure_not_required_over_plain_http():
    results = cookies.analyze_cookies(
        ["session=abc123; HttpOnly; SameSite=Strict"], is_https=False
    )
    assert results[0].status == "pass"


def test_multiple_cookies_each_evaluated_independently():
    results = cookies.analyze_cookies(
        [
            "session=abc123; Secure; HttpOnly; SameSite=Strict",
            "tracking=xyz",
        ],
        is_https=True,
    )
    assert len(results) == 2
    assert results[0].status == "pass"
    assert results[1].status == "fail"
