from datetime import timedelta

import requests

from webauditor.fetcher import USER_AGENT, fetch, fetch_path


class FakeHeaders(dict):
    """Mimics requests' CaseInsensitiveDict just enough for these tests."""


class FakeRawHeaders:
    def __init__(self, set_cookies):
        self._set_cookies = set_cookies

    def getlist(self, name):
        if name == "Set-Cookie":
            return self._set_cookies
        return []


class FakeRaw:
    def __init__(self, set_cookies):
        self.headers = FakeRawHeaders(set_cookies)


class FakeResponse:
    def __init__(self, url, status_code=200, headers=None, text="", history=None, set_cookies=None):
        self.url = url
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.history = history or []
        self.elapsed = timedelta(seconds=0.123)
        self.raw = FakeRaw(set_cookies or [])


class FakeSession:
    def __init__(self, response=None, exception=None):
        self._response = response
        self._exception = exception
        self.last_request_headers = None
        self.last_url = None

    def get(self, url, timeout=None, headers=None, allow_redirects=True):
        self.last_request_headers = headers
        self.last_url = url
        if self._exception:
            raise self._exception
        return self._response


def test_fetch_returns_normalized_result_on_success():
    session = FakeSession(FakeResponse("https://example.com/", 200, {"Server": "nginx"}, "hello"))
    result = fetch("https://example.com", session=session)

    assert result.ok
    assert result.status_code == 200
    assert result.headers["Server"] == "nginx"
    assert result.body_preview == "hello"
    assert result.final_url == "https://example.com/"


def test_fetch_sends_identifying_user_agent():
    session = FakeSession(FakeResponse("https://example.com/"))
    fetch("https://example.com", session=session)
    assert session.last_request_headers["User-Agent"] == USER_AGENT


def test_fetch_captures_network_error_without_raising():
    session = FakeSession(exception=requests.ConnectionError("refused"))
    result = fetch("https://unreachable.example", session=session)

    assert not result.ok
    assert result.status_code == 0
    assert "refused" in result.error


def test_fetch_captures_redirect_chain():
    hop = FakeResponse("https://example.com/old")
    final = FakeResponse("https://example.com/new", history=[hop])
    session = FakeSession(final)

    result = fetch("https://example.com/old", session=session)
    assert result.redirect_chain == ["https://example.com/old"]


def test_fetch_splits_multiple_set_cookie_headers():
    cookies = ["a=1; Secure", "b=2; HttpOnly"]
    session = FakeSession(FakeResponse("https://example.com/", set_cookies=cookies))

    result = fetch("https://example.com", session=session)
    assert result.set_cookie_headers == cookies


def test_fetch_path_joins_base_and_path_cleanly():
    session = FakeSession(FakeResponse("https://example.com/.git/HEAD"))
    fetch_path("https://example.com/", "/.git/HEAD", session=session)
    assert session.last_url == "https://example.com/.git/HEAD"
