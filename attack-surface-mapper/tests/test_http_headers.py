import requests

from asm import http_headers


class FakeResponse:
    def __init__(self, url, headers, status_code=200):
        self.url = url
        self.headers = headers
        self.status_code = status_code


class FakeSession:
    def __init__(self, responses):
        self.responses = responses  # {url_prefix: FakeResponse | Exception}

    def get(self, url, timeout=None, allow_redirects=True):
        for prefix, outcome in self.responses.items():
            if url.startswith(prefix):
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome
        raise requests.ConnectionError("no route configured for " + url)


ALL_SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}


def test_analyze_reports_none_for_unreachable_host():
    session = FakeSession(
        {
            "https://": requests.ConnectionError("refused"),
            "http://": requests.ConnectionError("refused"),
        }
    )
    result = http_headers.analyze("example.com", session=session)
    assert result == {"https": None, "http": None}


def test_analyze_describes_reachable_responses():
    session = FakeSession(
        {
            "https://": FakeResponse("https://example.com/", ALL_SECURE_HEADERS),
            "http://": FakeResponse("https://example.com/", {}),
        }
    )
    result = http_headers.analyze("example.com", session=session)
    assert result["https"] == {
        "status_code": 200,
        "final_url": "https://example.com/",
        "headers": ALL_SECURE_HEADERS,
    }
    assert result["http"]["final_url"] == "https://example.com/"


def test_build_findings_unreachable_host_is_info_only():
    findings = http_headers.build_findings("example.com", {"https": None, "http": None})
    assert len(findings) == 1
    assert findings[0].severity.name == "INFO"


def test_build_findings_no_missing_headers_when_all_present_and_https_redirect():
    result = {
        "https": {
            "status_code": 200,
            "final_url": "https://example.com/",
            "headers": ALL_SECURE_HEADERS,
        },
        "http": {"status_code": 301, "final_url": "https://example.com/", "headers": {}},
    }
    findings = http_headers.build_findings("example.com", result)
    assert findings == []


def test_build_findings_flags_missing_headers():
    result = {
        "https": {"status_code": 200, "final_url": "https://example.com/", "headers": {}},
        "http": {"status_code": 200, "final_url": "https://example.com/", "headers": {}},
    }
    findings = http_headers.build_findings("example.com", result)
    titles = {f.title for f in findings}
    assert "Missing Strict-Transport-Security header" in titles
    assert "Missing Content-Security-Policy header" in titles


def test_build_findings_flags_server_banner_disclosure():
    headers = dict(ALL_SECURE_HEADERS)
    headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    result = {
        "https": {"status_code": 200, "final_url": "https://example.com/", "headers": headers},
        "http": {"status_code": 200, "final_url": "https://example.com/", "headers": {}},
    }
    findings = http_headers.build_findings("example.com", result)
    assert any(f.title == "Server banner disclosed" for f in findings)


def test_build_findings_flags_https_unavailable():
    result = {
        "https": None,
        "http": {"status_code": 200, "final_url": "http://example.com/", "headers": {}},
    }
    findings = http_headers.build_findings("example.com", result)
    assert any(f.title == "HTTPS not available" for f in findings)


def test_build_findings_flags_http_not_redirecting_to_https():
    result = {
        "https": {"status_code": 200, "final_url": "https://example.com/", "headers": ALL_SECURE_HEADERS},
        "http": {"status_code": 200, "final_url": "http://example.com/", "headers": {}},
    }
    findings = http_headers.build_findings("example.com", result)
    assert any(f.title == "Plaintext HTTP does not redirect to HTTPS" for f in findings)
