import datetime as dt

from http_audit.fetcher import HttpResponse, TLSInfo
from http_audit.tls import check_tls


def _https_response(tls: TLSInfo | None) -> HttpResponse:
    return HttpResponse(url="https://example.com/", status=200, tls=tls)


def test_plain_http_is_critical():
    response = HttpResponse(url="http://example.com/", status=200)
    findings = check_tls(response)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_missing_tls_info_is_informational():
    findings = check_tls(_https_response(None))
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_weak_protocol_flagged_high():
    tls = TLSInfo(protocol_version="TLSv1.1", not_after=None, issuer=None, days_until_expiry=None)
    findings = check_tls(_https_response(tls))
    proto = next(f for f in findings if f.name == "TLS protocol version")
    assert proto.severity == "high"


def test_modern_protocol_passes():
    tls = TLSInfo(protocol_version="TLSv1.3", not_after=None, issuer=None, days_until_expiry=None)
    findings = check_tls(_https_response(tls))
    proto = next(f for f in findings if f.name == "TLS protocol version")
    assert proto.severity == "pass"


def test_expired_cert_is_critical():
    tls = TLSInfo(protocol_version="TLSv1.3", not_after=dt.datetime(2020, 1, 1), issuer="Example CA", days_until_expiry=-10)
    findings = check_tls(_https_response(tls))
    expiry = next(f for f in findings if f.name == "Certificate expiry")
    assert expiry.severity == "critical"


def test_soon_expiring_cert_is_medium():
    tls = TLSInfo(protocol_version="TLSv1.3", not_after=None, issuer="Example CA", days_until_expiry=10)
    findings = check_tls(_https_response(tls))
    expiry = next(f for f in findings if f.name == "Certificate expiry")
    assert expiry.severity == "medium"


def test_healthy_cert_passes():
    tls = TLSInfo(protocol_version="TLSv1.3", not_after=None, issuer="Example CA", days_until_expiry=200)
    findings = check_tls(_https_response(tls))
    expiry = next(f for f in findings if f.name == "Certificate expiry")
    assert expiry.severity == "pass"
