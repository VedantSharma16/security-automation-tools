from webrecon.security_headers import grade_headers, letter_grade


def test_letter_grade_boundaries():
    assert letter_grade(100) == "A"
    assert letter_grade(90) == "A"
    assert letter_grade(89) == "B"
    assert letter_grade(60) == "C"
    assert letter_grade(40) == "D"
    assert letter_grade(0) == "F"


def test_grade_headers_all_present_scores_perfectly():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Permissions-Policy": "geolocation=()",
        "Referrer-Policy": "no-referrer",
    }

    report = grade_headers(headers, is_https=True)

    assert report["score"] == 100
    assert report["grade"] == "A"
    assert report["findings"] == []


def test_grade_headers_flags_missing_headers():
    report = grade_headers({}, is_https=True)

    assert report["score"] == 0
    assert report["grade"] == "F"
    missing = {f["header"] for f in report["findings"]}
    assert "content-security-policy" in missing
    assert "strict-transport-security" in missing


def test_grade_headers_skips_hsts_over_plain_http():
    https_report = grade_headers({}, is_https=True)
    http_report = grade_headers({}, is_https=False)

    https_headers = {f["header"] for f in https_report["findings"]}
    http_headers = {f["header"] for f in http_report["findings"]}

    assert "strict-transport-security" in https_headers
    assert "strict-transport-security" not in http_headers


def test_grade_headers_flags_info_disclosure():
    report = grade_headers({"Server": "Apache/2.4.41 (Ubuntu)"}, is_https=False)
    disclosures = [f for f in report["findings"] if f["header"] == "server"]
    assert len(disclosures) == 1
    assert "Apache/2.4.41" in disclosures[0]["message"]


def test_grade_headers_flags_insecure_cookie():
    report = grade_headers({"Set-Cookie": "session=abc; Path=/"}, is_https=True)
    cookie_findings = [f for f in report["findings"] if f["header"] == "set-cookie"]
    messages = " ".join(f["message"] for f in cookie_findings)
    assert "Secure" in messages
    assert "HttpOnly" in messages
    assert "SameSite" in messages


def test_grade_headers_accepts_fully_hardened_cookie():
    report = grade_headers({"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Strict"}, is_https=True)
    cookie_findings = [f for f in report["findings"] if f["header"] == "set-cookie"]
    assert cookie_findings == []
