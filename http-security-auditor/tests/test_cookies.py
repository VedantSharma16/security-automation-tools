from http_audit.cookies import check_cookies
from http_audit.fetcher import HttpResponse


def _response(set_cookie_headers: list[str], https: bool = True) -> HttpResponse:
    scheme = "https" if https else "http"
    return HttpResponse(url=f"{scheme}://example.com/", status=200, set_cookie_headers=set_cookie_headers)


def test_no_cookies_is_informational():
    findings = check_cookies(_response([]))
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_fully_hardened_cookie_passes():
    findings = check_cookies(_response(["session=abc123; Secure; HttpOnly; SameSite=Strict"]))
    assert len(findings) == 1
    assert findings[0].severity == "pass"


def test_missing_secure_on_https_flagged_high():
    findings = check_cookies(_response(["session=abc123; HttpOnly; SameSite=Strict"], https=True))
    secure_findings = [f for f in findings if "Secure" in f.name]
    assert len(secure_findings) == 1
    assert secure_findings[0].severity == "high"


def test_missing_secure_on_http_not_flagged():
    findings = check_cookies(_response(["session=abc123; HttpOnly; SameSite=Strict"], https=False))
    secure_findings = [f for f in findings if "Secure" in f.name]
    assert secure_findings == []


def test_missing_httponly_flagged_medium():
    findings = check_cookies(_response(["session=abc123; Secure; SameSite=Strict"]))
    httponly_findings = [f for f in findings if "HttpOnly" in f.name]
    assert len(httponly_findings) == 1
    assert httponly_findings[0].severity == "medium"


def test_missing_samesite_flagged_low():
    findings = check_cookies(_response(["session=abc123; Secure; HttpOnly"]))
    samesite_findings = [f for f in findings if "SameSite" in f.name]
    assert len(samesite_findings) == 1
    assert samesite_findings[0].severity == "low"


def test_multiple_cookies_evaluated_independently():
    findings = check_cookies(
        _response(
            [
                "good=1; Secure; HttpOnly; SameSite=Strict",
                "bad=2",
            ]
        )
    )
    good_findings = [f for f in findings if "'good'" in f.name]
    bad_findings = [f for f in findings if "'bad'" in f.name]
    assert len(good_findings) == 1 and good_findings[0].severity == "pass"
    assert len(bad_findings) == 3  # missing Secure, HttpOnly, and SameSite
