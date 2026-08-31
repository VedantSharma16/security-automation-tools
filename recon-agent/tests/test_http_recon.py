from __future__ import annotations

import urllib.error
from email.message import Message

from recon_agent import http_recon


class FakeResponse:
    def __init__(self, status: int, headers: dict, body: bytes = b""):
        self.status = status
        self._headers = list(headers.items())
        self._body = body

    def getheaders(self):
        return self._headers

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    def __init__(self, response=None, error: Exception | None = None):
        self._response = response
        self._error = error
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        if self._error is not None:
            raise self._error
        return self._response


def test_fetch_headers_flags_missing_security_headers():
    opener = FakeOpener(FakeResponse(200, {"Server": "nginx/1.18.0", "Content-Type": "text/html"}))

    finding = http_recon.fetch_headers("https://example.com", opener=opener)

    assert finding.ok
    assert finding.status == 200
    assert "strict-transport-security" in finding.missing_security_headers
    assert "content-security-policy" in finding.missing_security_headers
    assert finding.fingerprint == {"server": "nginx/1.18.0"}


def test_fetch_headers_reports_no_missing_headers_when_all_present():
    headers = {h: "present" for h in http_recon.SECURITY_HEADERS}
    opener = FakeOpener(FakeResponse(200, headers))

    finding = http_recon.fetch_headers("https://example.com", opener=opener)

    assert finding.missing_security_headers == []


def test_fetch_headers_handles_http_error_with_headers():
    hdrs = Message()
    hdrs["Server"] = "Apache"
    error = urllib.error.HTTPError("https://example.com", 403, "Forbidden", hdrs, None)
    opener = FakeOpener(error=error)

    finding = http_recon.fetch_headers("https://example.com", opener=opener)

    assert finding.ok
    assert finding.status == 403
    assert finding.fingerprint == {"server": "Apache"}


def test_fetch_headers_handles_connection_failure():
    opener = FakeOpener(error=urllib.error.URLError("connection refused"))

    finding = http_recon.fetch_headers("https://unreachable.example", opener=opener)

    assert not finding.ok
    assert "connection refused" in finding.error


def test_fetch_robots_parses_disallow_and_sitemap():
    body = (
        b"User-agent: *\n"
        b"Disallow: /admin\n"
        b"Disallow: /private\n"
        b"# a comment\n"
        b"Sitemap: https://example.com/sitemap.xml\n"
    )
    opener = FakeOpener(FakeResponse(200, {}, body=body))

    finding = http_recon.fetch_robots("https://example.com", opener=opener)

    assert finding.fetched
    assert finding.disallowed_paths == ["/admin", "/private"]
    assert finding.sitemaps == ["https://example.com/sitemap.xml"]


def test_fetch_robots_missing_is_not_an_error():
    error = urllib.error.HTTPError("https://example.com/robots.txt", 404, "Not Found", None, None)
    opener = FakeOpener(error=error)

    finding = http_recon.fetch_robots("https://example.com", opener=opener)

    assert finding.fetched is False
    assert finding.error is None
