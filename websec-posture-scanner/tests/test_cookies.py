from webscan.checks.cookies import check_cookies
from webscan.models import ScanTarget


def _target(cookies: list[str], scheme: str = "https") -> ScanTarget:
    url = f"{scheme}://example.com/"
    return ScanTarget(url=url, final_url=url, status_code=200, cookies=cookies)


def test_fully_hardened_cookie_has_no_findings():
    cookies = ["session=abc; Secure; HttpOnly; SameSite=Lax"]
    assert check_cookies(_target(cookies)) == []


def test_missing_secure_on_https():
    cookies = ["session=abc; HttpOnly; SameSite=Lax"]
    findings = check_cookies(_target(cookies))
    ids = [f.id for f in findings]
    assert "cookie-missing-secure-session" in ids


def test_missing_secure_not_flagged_on_http():
    cookies = ["foo=bar; HttpOnly; SameSite=Lax"]
    findings = check_cookies(_target(cookies, scheme="http"))
    assert not any(f.id.startswith("cookie-missing-secure") for f in findings)


def test_missing_httponly():
    cookies = ["session=abc; Secure; SameSite=Lax"]
    findings = check_cookies(_target(cookies))
    assert "cookie-missing-httponly-session" in [f.id for f in findings]


def test_sensitive_cookie_name_bumps_severity():
    sensitive = check_cookies(_target(["auth_token=abc; SameSite=Lax"]))
    generic = check_cookies(_target(["preference=abc; SameSite=Lax"]))

    sensitive_secure = next(f for f in sensitive if f.id.startswith("cookie-missing-secure"))
    generic_secure = next(f for f in generic if f.id.startswith("cookie-missing-secure"))
    assert sensitive_secure.severity == "high"
    assert generic_secure.severity == "medium"


def test_samesite_none_without_secure_is_high():
    cookies = ["session=abc; HttpOnly; SameSite=None"]
    findings = check_cookies(_target(cookies))
    match = next(f for f in findings if f.id == "cookie-samesite-none-without-secure-session")
    assert match.severity == "high"


def test_missing_samesite():
    cookies = ["session=abc; Secure; HttpOnly"]
    findings = check_cookies(_target(cookies))
    assert "cookie-missing-samesite-session" in [f.id for f in findings]


def test_multiple_cookies_each_evaluated_independently():
    cookies = [
        "session=abc; Secure; HttpOnly; SameSite=Lax",
        "tracking=xyz",
    ]
    findings = check_cookies(_target(cookies))
    tracking_ids = [f.id for f in findings if f.id.endswith("-tracking")]
    assert len(tracking_ids) >= 2
    assert not any(f.id.endswith("-session") for f in findings)
