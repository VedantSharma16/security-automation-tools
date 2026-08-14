"""Shared pytest fixtures/helpers. No test in this suite makes a real network call."""

from __future__ import annotations

import pytest

from asmapper.fetcher import FetchResult


def make_result(url: str, status: int = 200, headers: dict | None = None, body: str = "") -> FetchResult:
    return FetchResult(url=url, status=status, headers=headers or {}, body=body, elapsed_ms=1.0)


class FakeFetcher:
    """A fetch_fn double keyed by exact URL, with a fallback 404 for anything unregistered."""

    def __init__(self):
        self._responses: dict[str, FetchResult] = {}
        self.calls: list[str] = []

    def register(self, url: str, result: FetchResult) -> None:
        self._responses[url] = result

    def __call__(self, url: str, timeout: float = 8.0, method: str = "GET") -> FetchResult:
        self.calls.append(url)
        return self._responses.get(url, make_result(url, status=404, body="not found"))


@pytest.fixture
def fake_fetcher() -> FakeFetcher:
    return FakeFetcher()
