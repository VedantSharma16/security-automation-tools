import email.message
import io
import socket
import urllib.error

import pytest

from webauditor.fetch import Fetcher


class _FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, status: int, headers: email.message.Message):
        super().__init__(body)
        self.status = status
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


def _headers(pairs: list[tuple[str, str]]) -> email.message.Message:
    msg = email.message.Message()
    for key, value in pairs:
        msg[key] = value
    return msg


def test_get_returns_status_headers_and_body(monkeypatch):
    fake = _FakeResponse(b"hello world", 200, _headers([("Content-Type", "text/plain")]))
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: fake)

    result = Fetcher().get("https://example.com")

    assert result.status_code == 200
    assert result.headers["Content-Type"] == "text/plain"
    assert result.body == "hello world"
    assert result.ok is True


def test_get_captures_multiple_set_cookie_headers(monkeypatch):
    fake = _FakeResponse(
        b"",
        200,
        _headers([("Set-Cookie", "a=1; Secure"), ("Set-Cookie", "b=2; Secure")]),
    )
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: fake)

    result = Fetcher().get("https://example.com")

    assert result.set_cookie_headers == ["a=1; Secure", "b=2; Secure"]


def test_http_error_is_captured_not_raised(monkeypatch):
    def raise_http_error(req, timeout=None):
        raise urllib.error.HTTPError(
            "https://example.com", 404, "Not Found", _headers([]), io.BytesIO(b"nope")
        )

    monkeypatch.setattr("urllib.request.urlopen", raise_http_error)

    result = Fetcher().get("https://example.com")

    assert result.status_code == 404
    assert result.body == "nope"
    assert result.ok is True  # a valid HTTP response, even if 404


def test_connection_failure_sets_error_not_ok(monkeypatch):
    def raise_url_error(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", raise_url_error)

    result = Fetcher().get("https://example.com")

    assert result.status_code is None
    assert result.error is not None
    assert result.ok is False


def test_timeout_is_captured_not_raised(monkeypatch):
    def raise_timeout(req, timeout=None):
        raise socket.timeout("timed out")

    monkeypatch.setattr("urllib.request.urlopen", raise_timeout)

    result = Fetcher().get("https://example.com")

    assert result.ok is False
    assert "timed out" in result.error
