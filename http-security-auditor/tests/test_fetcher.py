import datetime as dt

import pytest

from http_audit.fetcher import (
    FetchError,
    HttpResponse,
    _issuer_common_name,
    _parse_cert_not_after,
    live_fetch,
)


def test_http_response_get_header_is_case_insensitive():
    response = HttpResponse(url="https://example.com/", status=200, headers={"content-type": "text/html"})
    assert response.get_header("Content-Type") == "text/html"
    assert response.get_header("missing") is None


def test_live_fetch_rejects_unsupported_scheme():
    with pytest.raises(FetchError):
        live_fetch("ftp://example.com/")


def test_live_fetch_rejects_url_without_host():
    with pytest.raises(FetchError):
        live_fetch("https:///path-only")


def test_parse_cert_not_after_valid_format():
    parsed = _parse_cert_not_after({"notAfter": "Jan 01 00:00:00 2030 GMT"})
    assert parsed == dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)


def test_parse_cert_not_after_missing_field():
    assert _parse_cert_not_after({}) is None


def test_parse_cert_not_after_malformed_value():
    assert _parse_cert_not_after({"notAfter": "not-a-date"}) is None


def test_issuer_common_name_extracted():
    cert = {"issuer": ((("countryName", "US"),), (("commonName", "Example CA"),))}
    assert _issuer_common_name(cert) == "Example CA"


def test_issuer_common_name_missing():
    assert _issuer_common_name({"issuer": ()}) is None
