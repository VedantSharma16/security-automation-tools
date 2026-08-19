from webrecon.http_probe import HttpResponse, default_transport, fetch


def test_fetch_rejects_unsupported_scheme():
    result = fetch("ftp://example.test/file")
    assert result.status_code == 0
    assert "unsupported URL scheme" in result.error


def test_fetch_uses_injected_transport():
    calls = []

    def fake_transport(url, timeout):
        calls.append((url, timeout))
        return HttpResponse(url=url, status_code=200, headers={"Server": "test"}, body="ok", elapsed_ms=1.0)

    result = fetch("https://example.test", timeout=3.0, transport=fake_transport)

    assert calls == [("https://example.test", 3.0)]
    assert result.status_code == 200
    assert result.body == "ok"


def test_default_transport_against_local_server(local_http_server):
    result = default_transport(local_http_server, timeout=5.0)

    assert result.error is None
    assert result.status_code == 200
    assert result.headers["Server"] == "nginx/1.18.0"
    assert "hello" in result.body
    assert result.elapsed_ms >= 0


def test_default_transport_reports_connection_error():
    # nothing listening on this port -- must fail fast, not raise
    result = default_transport("http://127.0.0.1:1", timeout=1.0)

    assert result.status_code == 0
    assert result.error is not None
