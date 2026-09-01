"""Shared test doubles for the HTTP layer -- no real sockets are used."""

from __future__ import annotations

import urllib.error


class FakeResponse:
    def __init__(self, url, status=200, headers=None, body=b""):
        self._url = url
        self.status = status
        self.headers = _HeaderView(headers or [])
        self._body = body

    def geturl(self):
        return self._url

    def read(self, _n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class _HeaderView:
    """Mimics the subset of http.client.HTTPMessage used by fetcher.py."""

    def __init__(self, items):
        self._items = list(items)

    def items(self):
        return list(self._items)


class FakeOpener:
    """Drop-in replacement for urllib.request.OpenerDirector.

    ``responses`` maps a URL to either a FakeResponse or an exception
    instance to raise.
    """

    def __init__(self, responses: dict):
        self.responses = responses
        self.requested_urls: list[str] = []

    def open(self, request, timeout=None):
        url = request.full_url
        self.requested_urls.append(url)
        outcome = self.responses.get(url)
        if outcome is None:
            raise urllib.error.URLError(f"no fake response configured for {url}")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
