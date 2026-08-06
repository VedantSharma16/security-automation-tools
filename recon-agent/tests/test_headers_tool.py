from recon_agent.tools import headers_tool
from recon_agent.tools.headers_tool import FetchResult


def test_normalize_url_adds_https_scheme():
    assert headers_tool.normalize_url("example.com") == "https://example.com"
    assert headers_tool.normalize_url("http://example.com") == "http://example.com"


def test_analyze_headers_flags_http_scheme():
    findings = headers_tool.analyze_headers("http://example.com", {})
    titles = {f.title for f in findings}
    assert "Site not served over HTTPS" in titles


def test_analyze_headers_flags_missing_security_headers_on_https():
    findings = headers_tool.analyze_headers("https://example.com", {})
    titles = {f.title for f in findings}
    assert "Missing Strict-Transport-Security header" in titles
    assert "Missing Content-Security-Policy header" in titles
    assert "Missing X-Content-Type-Options header" in titles
    assert "Missing clickjacking protection" in titles
    assert "Missing Referrer-Policy header" in titles


def test_analyze_headers_clean_response_has_no_findings():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }
    findings = headers_tool.analyze_headers("https://example.com", headers)
    assert findings == []


def test_analyze_headers_frame_ancestors_satisfies_clickjacking_check():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    findings = headers_tool.analyze_headers("https://example.com", headers)
    titles = {f.title for f in findings}
    assert "Missing clickjacking protection" not in titles


def test_analyze_headers_flags_server_banner_disclosure():
    findings = headers_tool.analyze_headers("https://example.com", {"Server": "Apache/2.4.41 (Ubuntu)"})
    titles = {f.title for f in findings}
    assert "Server/technology banner disclosed" in titles


def test_analyze_headers_flags_permissive_cors_with_credentials_as_critical():
    headers = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
    findings = headers_tool.analyze_headers("https://example.com", headers)
    critical = [f for f in findings if f.severity == "critical"]
    assert any(f.title == "Permissive CORS combined with credentials" for f in critical)


def test_analyze_headers_flags_wildcard_cors_without_credentials_as_low():
    findings = headers_tool.analyze_headers("https://example.com", {"Access-Control-Allow-Origin": "*"})
    matches = [f for f in findings if f.title == "Wildcard CORS policy"]
    assert len(matches) == 1
    assert matches[0].severity == "low"


def test_analyze_headers_flags_cookie_flags():
    findings = headers_tool.analyze_headers("https://example.com", {"Set-Cookie": "session=abc123; Path=/"})
    titles = {f.title for f in findings}
    assert "Cookie missing Secure flag" in titles
    assert "Cookie missing HttpOnly flag" in titles
    assert "Cookie missing SameSite attribute" in titles


def test_analyze_headers_accepts_fully_flagged_cookie():
    headers = {"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict"}
    findings = headers_tool.analyze_headers("https://example.com", headers)
    titles = {f.title for f in findings}
    assert "Cookie missing Secure flag" not in titles
    assert "Cookie missing HttpOnly flag" not in titles
    assert "Cookie missing SameSite attribute" not in titles


def test_run_uses_injected_fetch_fn():
    def fake_fetch(url):
        return FetchResult(url=url, status_code=200, headers={"Server": "nginx"})

    result = headers_tool.run("example.com", fetch_fn=fake_fetch)
    assert result.tool == "http_headers"
    assert result.data["final_url"] == "https://example.com"
    assert any(f.title == "Server/technology banner disclosed" for f in result.findings)


def test_run_handles_fetch_failure_gracefully():
    def broken_fetch(url):
        raise ConnectionError("connection refused")

    result = headers_tool.run("example.com", fetch_fn=broken_fetch)
    assert result.data["error"] == "connection refused"
    assert result.findings[0].title == "HTTP request failed"
