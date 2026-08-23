import pytest

from recon.http_headers import FetchError, analyze_headers, fetch_headers


def make_fetcher(status=200, headers=None, final_url="https://example.com/"):
    headers = headers or {}

    def fetcher(url, timeout):
        return status, headers, final_url

    return fetcher


def test_fetch_headers_returns_status_and_headers():
    fetcher = make_fetcher(status=200, headers={"Server": "nginx"})
    result = fetch_headers("https://example.com/", fetcher=fetcher)
    assert result["status"] == 200
    assert result["headers"]["Server"] == "nginx"


def test_fetch_headers_raises_fetch_error_on_connection_failure():
    def broken_fetcher(url, timeout):
        raise OSError("connection refused")

    with pytest.raises(FetchError):
        fetch_headers("https://example.com/", fetcher=broken_fetcher)


def test_analyze_headers_flags_all_missing_security_headers():
    result = {"status": 200, "headers": {}, "final_url": "https://example.com/"}
    findings = analyze_headers(result)
    titles = {f.title for f in findings}
    assert "Missing Strict-Transport-Security header" in titles
    assert "Missing Content-Security-Policy header" in titles
    assert "Missing X-Frame-Options header" in titles


def test_analyze_headers_no_findings_when_fully_hardened():
    result = {
        "status": 200,
        "final_url": "https://example.com/",
        "headers": {
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    }
    findings = analyze_headers(result)
    assert findings == []


def test_analyze_headers_csp_frame_ancestors_satisfies_x_frame_options():
    result = {
        "status": 200,
        "final_url": "https://example.com/",
        "headers": {
            "Strict-Transport-Security": "max-age=1",
            "Content-Security-Policy": "frame-ancestors 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    }
    findings = analyze_headers(result)
    assert not any("X-Frame-Options" in f.title for f in findings)


def test_analyze_headers_flags_server_disclosure():
    result = {
        "status": 200,
        "final_url": "https://example.com/",
        "headers": {"Server": "Apache/2.4.41 (Ubuntu)"},
    }
    findings = analyze_headers(result)
    assert any(f.title.startswith("Server header") for f in findings)


def test_analyze_headers_flags_cookie_missing_flags():
    result = {
        "status": 200,
        "final_url": "https://example.com/",
        "headers": {"Set-Cookie": "session=abc123; Path=/"},
    }
    findings = analyze_headers(result)
    cookie_finding = next(f for f in findings if "Cookie" in f.title)
    assert cookie_finding.severity == "medium"
    assert set(cookie_finding.evidence["missing"]) == {"secure", "httponly", "samesite"}


def test_analyze_headers_cookie_with_all_flags_not_flagged():
    result = {
        "status": 200,
        "final_url": "https://example.com/",
        "headers": {"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict"},
    }
    findings = analyze_headers(result)
    assert not any("Cookie" in f.title for f in findings)
