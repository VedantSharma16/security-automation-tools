from datetime import datetime, timedelta, timezone

from recon_agent.http_fingerprint import extract_title, fingerprint_http, parse_not_after


def test_extract_title_found():
    assert extract_title("<html><head><title>Admin Panel</title></head></html>") == "Admin Panel"


def test_extract_title_missing_returns_none():
    assert extract_title("<html><body>hi</body></html>") is None


def test_parse_not_after_valid():
    parsed = parse_not_after("Jan  1 00:00:00 2030 GMT")
    assert parsed.year == 2030


def test_parse_not_after_invalid_returns_none():
    assert parse_not_after("not a date") is None


def test_fingerprint_http_success_over_https():
    def fake_http_fetcher(host, port, timeout, scheme):
        return 200, {"Server": "nginx"}, "<title>Grafana</title>"

    future_expiry = datetime.now(timezone.utc) + timedelta(days=10)

    def fake_tls_fetcher(host, port, timeout):
        return {"notAfter": future_expiry.strftime("%b %d %H:%M:%S %Y GMT")}

    fp = fingerprint_http(
        "host", 443, http_fetcher=fake_http_fetcher, tls_fetcher=fake_tls_fetcher
    )
    assert fp.status == 200
    assert fp.server == "nginx"
    assert fp.title == "Grafana"
    assert fp.scheme == "https"
    assert fp.tls_days_remaining in (9, 10)
    assert fp.error is None


def test_fingerprint_http_records_connection_error():
    def failing_fetcher(host, port, timeout, scheme):
        raise ConnectionRefusedError("refused")

    fp = fingerprint_http("host", 80, http_fetcher=failing_fetcher)
    assert fp.error == "refused"
    assert fp.status is None


def test_fingerprint_http_records_tls_error_without_failing_http():
    def fake_http_fetcher(host, port, timeout, scheme):
        return 200, {}, "<title>Self-signed box</title>"

    def failing_tls_fetcher(host, port, timeout):
        raise Exception("certificate verify failed")

    fp = fingerprint_http(
        "host", 443, http_fetcher=fake_http_fetcher, tls_fetcher=failing_tls_fetcher
    )
    assert fp.status == 200
    assert fp.error is None
    assert fp.tls_error == "certificate verify failed"
    assert fp.tls_days_remaining is None


def test_fingerprint_http_defaults_to_plain_http_scheme():
    def fake_http_fetcher(host, port, timeout, scheme):
        return 200, {}, ""

    fp = fingerprint_http("host", 8080, http_fetcher=fake_http_fetcher)
    assert fp.scheme == "http"
