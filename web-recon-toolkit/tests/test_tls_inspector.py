from datetime import datetime, timedelta, timezone

from webrecon.tls_inspector import TlsInfo, from_fixture, inspect


def cert_date(delta: timedelta) -> str:
    """Format a datetime the way real X.509 certs report notAfter (e.g. 'Aug 25 12:00:00 2026 GMT')."""
    when = datetime.now(timezone.utc) + delta
    return when.strftime("%b %d %H:%M:%S %Y") + " GMT"


def test_inspect_rejects_non_https_url():
    result = inspect("http://example.test")
    assert result.error == "not an https URL"
    assert result.days_until_expiry is None


def test_inspect_uses_injected_cert_fetcher():
    def fake_fetcher(host, port, timeout):
        return {
            "notAfter": cert_date(timedelta(days=90)),
            "subject": ((("commonName", host),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "_protocol_version": "TLSv1.3",
        }

    result = inspect("https://example.test", cert_fetcher=fake_fetcher)

    assert result.error is None
    assert result.host == "example.test"
    assert result.protocol_version == "TLSv1.3"
    assert result.subject == "commonName=example.test"
    assert result.issuer == "organizationName=Let's Encrypt"
    assert 89 <= result.days_until_expiry <= 90


def test_inspect_captures_connection_errors():
    def failing_fetcher(host, port, timeout):
        raise OSError("connection refused")

    result = inspect("https://example.test", cert_fetcher=failing_fetcher)

    assert result.error == "connection refused"
    assert result.days_until_expiry is None


def test_days_until_expiry_negative_for_expired_cert():
    result = from_fixture("example.test", {"not_after": cert_date(timedelta(days=-10))})
    assert result.days_until_expiry <= -9


def test_days_until_expiry_handles_malformed_date():
    result = from_fixture("example.test", {"not_after": "not-a-real-date"})
    assert result.days_until_expiry is None


def test_from_fixture_passthrough_fields():
    result = from_fixture("api.test", {
        "protocol_version": "TLSv1.2",
        "subject": "CN=api.test",
        "issuer": "CN=R3, O=Let's Encrypt",
        "not_after": cert_date(timedelta(days=30)),
    })
    assert isinstance(result, TlsInfo)
    assert result.subject == "CN=api.test"
    assert result.issuer == "CN=R3, O=Let's Encrypt"
