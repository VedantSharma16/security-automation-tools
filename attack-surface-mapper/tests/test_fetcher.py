from __future__ import annotations

import io
import urllib.error
from unittest.mock import MagicMock, patch

from asmapper.fetcher import fetch


class _FakeResponse:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self._headers = headers or [("Content-Type", "text/html; charset=utf-8")]
        self._body = body
        self.headers = MagicMock()
        self.headers.get_content_charset.return_value = "utf-8"

    def getheaders(self):
        return self._headers

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_fetch_success_returns_status_headers_and_body():
    fake_response = _FakeResponse(status=200, body=b"<html>hi</html>")
    with patch("asmapper.fetcher.urllib.request.urlopen", return_value=fake_response):
        result = fetch("https://example.com")

    assert result.ok
    assert result.status == 200
    assert result.body == "<html>hi</html>"
    assert result.headers["Content-Type"].startswith("text/html")


def test_fetch_http_error_still_returns_status_and_body():
    err = urllib.error.HTTPError(
        url="https://example.com/missing",
        code=404,
        msg="Not Found",
        hdrs={"Content-Type": "text/plain"},
        fp=io.BytesIO(b"nope"),
    )
    with patch("asmapper.fetcher.urllib.request.urlopen", side_effect=err):
        result = fetch("https://example.com/missing")

    assert result.status == 404
    assert result.ok  # a well-formed HTTP error response is still a successful fetch
    assert result.body == "nope"


def test_fetch_transport_failure_sets_error_and_not_ok():
    with patch("asmapper.fetcher.urllib.request.urlopen", side_effect=OSError("DNS resolution failed")):
        result = fetch("https://nonexistent.invalid")

    assert result.status is None
    assert not result.ok
    assert "DNS" in result.error
