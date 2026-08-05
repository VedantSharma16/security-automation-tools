from unittest.mock import MagicMock, patch

import requests

from websecaudit.fetcher import TLSInfo, fetch, probe_tls_connection


def _make_response(url="https://example.com", status_code=200, headers=None, history=None, set_cookie_list=None):
    resp = MagicMock()
    resp.url = url
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.history = history or []
    resp.elapsed.total_seconds.return_value = 0.123
    raw_headers = MagicMock()
    raw_headers.get_all.return_value = set_cookie_list
    resp.raw.headers = raw_headers
    return resp


@patch("websecaudit.fetcher.requests.get")
def test_fetch_normalizes_headers_to_lowercase(mock_get):
    mock_get.return_value = _make_response(
        headers={"Content-Type": "text/html", "X-Frame-Options": "DENY"}
    )
    result = fetch("https://example.com", probe_tls=False)
    assert result.headers["content-type"] == "text/html"
    assert result.headers["x-frame-options"] == "DENY"
    assert result.ok
    assert result.scheme == "https"


@patch("websecaudit.fetcher.requests.get")
def test_fetch_extracts_multiple_set_cookie_headers(mock_get):
    mock_get.return_value = _make_response(
        set_cookie_list=["a=1; Secure", "b=2; HttpOnly"]
    )
    result = fetch("https://example.com", probe_tls=False)
    assert result.set_cookie_headers == ["a=1; Secure", "b=2; HttpOnly"]


@patch("websecaudit.fetcher.requests.get")
def test_fetch_falls_back_to_single_set_cookie_header(mock_get):
    resp = _make_response(headers={"Set-Cookie": "a=1; Secure"}, set_cookie_list=None)
    mock_get.return_value = resp
    result = fetch("https://example.com", probe_tls=False)
    assert result.set_cookie_headers == ["a=1; Secure"]


@patch("websecaudit.fetcher.requests.get")
def test_fetch_records_redirect_chain(mock_get):
    hop = MagicMock(url="http://example.com/", status_code=301)
    mock_get.return_value = _make_response(history=[hop])
    result = fetch("http://example.com", probe_tls=False)
    assert result.redirect_chain == [("http://example.com/", 301)]


@patch("websecaudit.fetcher.requests.get", side_effect=requests.exceptions.ConnectionError("boom"))
def test_fetch_request_exception_returns_error_result(mock_get):
    result = fetch("https://unreachable.example", probe_tls=False)
    assert not result.ok
    assert "boom" in result.error
    assert result.status_code == 0


@patch("websecaudit.fetcher.probe_tls_connection")
@patch("websecaudit.fetcher.requests.get")
def test_fetch_probes_tls_for_https_final_url(mock_get, mock_probe):
    mock_get.return_value = _make_response(url="https://example.com")
    mock_probe.return_value = TLSInfo(protocol_version="TLSv1.3")
    result = fetch("https://example.com")
    assert result.tls.protocol_version == "TLSv1.3"
    mock_probe.assert_called_once()


@patch("websecaudit.fetcher.probe_tls_connection")
@patch("websecaudit.fetcher.requests.get")
def test_fetch_skips_tls_probe_for_http(mock_get, mock_probe):
    mock_get.return_value = _make_response(url="http://example.com")
    result = fetch("http://example.com")
    assert result.tls is None
    mock_probe.assert_not_called()


def test_probe_tls_connection_success():
    mock_tls_sock = MagicMock()
    mock_tls_sock.getpeercert.return_value = {"notAfter": "Jan  1 00:00:00 2099 GMT"}
    mock_tls_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_tls_sock.version.return_value = "TLSv1.3"

    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_tls_sock

    with patch("websecaudit.fetcher.socket.create_connection") as mock_create_conn, \
            patch("websecaudit.fetcher.ssl.create_default_context", return_value=mock_ctx):
        mock_create_conn.return_value.__enter__.return_value = MagicMock()
        info = probe_tls_connection("example.com", 443, timeout=5)

    assert info.protocol_version == "TLSv1.3"
    assert info.cipher == "TLS_AES_256_GCM_SHA384"
    assert info.days_until_expiry is not None and info.days_until_expiry > 1000
    assert info.error is None


def test_probe_tls_connection_handles_socket_error():
    with patch("websecaudit.fetcher.socket.create_connection", side_effect=OSError("refused")):
        info = probe_tls_connection("example.com", 443, timeout=5)
    assert info.error == "refused"
    assert info.protocol_version is None
