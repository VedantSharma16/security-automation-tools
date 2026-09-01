import urllib.error

import pytest

from tests.fakes import FakeOpener, FakeResponse
from websec_auditor.fetcher import fetch, fetch_well_known, normalize_url


def test_normalize_url_adds_https_scheme_when_missing():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_rejects_unsupported_scheme():
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")


def test_fetch_success_returns_headers_and_body():
    url = "https://example.com/"
    opener = FakeOpener({url: FakeResponse(url, status=200, headers=[("Content-Type", "text/html")], body=b"hi")})
    result = fetch(url, opener=opener)
    assert result.ok
    assert result.status == 200
    assert result.header("content-type") == "text/html"
    assert result.body == b"hi"
    assert opener.requested_urls == [url]


def test_fetch_preserves_repeated_headers():
    url = "https://example.com/"
    opener = FakeOpener(
        {
            url: FakeResponse(
                url,
                headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")],
            )
        }
    )
    result = fetch(url, opener=opener)
    assert result.all_headers("Set-Cookie") == ["a=1", "b=2"]


def test_fetch_handles_url_error_without_raising():
    url = "https://unreachable.example/"
    opener = FakeOpener({url: urllib.error.URLError("name resolution failed")})
    result = fetch(url, opener=opener)
    assert not result.ok
    assert result.error is not None
    assert result.status == 0


def test_fetch_handles_http_error_without_raising():
    url = "https://example.com/missing"
    error = urllib.error.HTTPError(url, 404, "Not Found", None, None)
    opener = FakeOpener({url: error})
    result = fetch(url, opener=opener)
    assert result.status == 404
    assert not result.ok
    assert result.error is None  # a 404 is a valid HTTP response, not a network failure


def test_fetch_well_known_hits_expected_paths():
    base = "https://example.com/"
    robots_url = "https://example.com/robots.txt"
    security_url = "https://example.com/.well-known/security.txt"
    opener = FakeOpener(
        {
            robots_url: FakeResponse(robots_url, status=200),
            security_url: FakeResponse(security_url, status=404),
        }
    )
    results = fetch_well_known(base, ["robots.txt", ".well-known/security.txt"], opener=opener)
    assert results["robots.txt"].status == 200
    assert results[".well-known/security.txt"].status == 404
