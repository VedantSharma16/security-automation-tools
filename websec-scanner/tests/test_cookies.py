from __future__ import annotations

from websec.checks.cookies import check_cookies


def test_flags_missing_httponly_and_samesite():
    raw = ["session_id=abc123; Path=/"]
    findings = check_cookies("http://example.test/", raw, is_https=False)
    titles = {f.title for f in findings}
    assert "Cookie 'session_id' missing HttpOnly flag" in titles
    assert "Cookie 'session_id' missing or weak SameSite attribute" in titles
    # Secure is only meaningful/expected over HTTPS.
    assert not any("Secure flag" in t for t in titles)


def test_flags_missing_secure_over_https():
    raw = ["session_id=abc123; Path=/; HttpOnly; SameSite=Lax"]
    findings = check_cookies("https://example.test/", raw, is_https=True)
    assert any("Secure flag" in f.title for f in findings)


def test_well_configured_cookie_has_no_findings():
    raw = ["session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"]
    findings = check_cookies("https://example.test/", raw, is_https=True)
    assert findings == []


def test_handles_multiple_distinct_set_cookie_headers():
    raw = [
        "a=1; Path=/; Secure; HttpOnly; SameSite=Strict",
        "b=2; Path=/",
    ]
    findings = check_cookies("https://example.test/", raw, is_https=True)
    flagged_names = {f.title.split("'")[1] for f in findings}
    assert flagged_names == {"b"}
