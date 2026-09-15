from datetime import datetime, timedelta, timezone

from recon_agent.http_recon import audit_security_headers, fetch_headers, fetch_tls_certificate


def test_fetch_headers_success():
    def fetcher(url, timeout):
        return 200, {"Server": "nginx", "Content-Type": "text/html"}

    result = fetch_headers("https://example.com/", fetcher=fetcher)
    assert result.status == 200
    assert result.headers["server"] == "nginx"
    assert result.error is None


def test_fetch_headers_failure_is_captured_not_raised():
    def fetcher(url, timeout):
        raise ConnectionRefusedError("refused")

    result = fetch_headers("https://example.com/", fetcher=fetcher)
    assert result.status is None
    assert result.error is not None


def test_audit_security_headers_flags_missing():
    findings = audit_security_headers({"server": "nginx"})
    headers_flagged = {f.header for f in findings}
    assert "content-security-policy" in headers_flagged
    assert "strict-transport-security" in headers_flagged


def test_audit_security_headers_none_missing_when_all_present():
    all_present = {
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }
    assert audit_security_headers(all_present) == []


def _cert_expiring_in(days: int) -> dict:
    expiry = datetime.now(timezone.utc) + timedelta(days=days)
    return {
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
        "issuer": ((("organizationName", "Example CA"),),),
    }


def test_fetch_tls_certificate_reports_days_remaining():
    result = fetch_tls_certificate("example.com", cert_getter=lambda h, p, t: _cert_expiring_in(90))
    assert result.fetched is True
    assert result.days_remaining in (89, 90)
    assert result.issuer == "organizationName=Example CA"


def test_fetch_tls_certificate_negative_days_when_expired():
    result = fetch_tls_certificate("example.com", cert_getter=lambda h, p, t: _cert_expiring_in(-5))
    assert result.days_remaining < 0


def test_fetch_tls_certificate_error_is_captured():
    def cert_getter(hostname, port, timeout):
        raise OSError("connection reset")

    result = fetch_tls_certificate("example.com", cert_getter=cert_getter)
    assert result.fetched is False
    assert result.error is not None
