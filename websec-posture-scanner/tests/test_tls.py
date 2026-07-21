from webscan.checks.tls import check_tls
from webscan.models import TLSInfo


def _tls(**overrides) -> TLSInfo:
    base = dict(
        hostname="example.com",
        port=443,
        protocol_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        not_before="Jan  1 00:00:00 2024 GMT",
        not_after="Jan  1 00:00:00 2027 GMT",
        days_until_expiry=365,
        issuer="C=US,O=Example CA",
        subject="CN=example.com",
        san=["example.com"],
    )
    base.update(overrides)
    return TLSInfo(**base)


def test_none_tls_no_findings():
    assert check_tls(None) == []


def test_healthy_cert_no_findings():
    assert check_tls(_tls()) == []


def test_handshake_error_reported():
    findings = check_tls(TLSInfo(hostname="example.com", port=443, error="SSLCertVerificationError: bad cert"))
    assert len(findings) == 1
    assert findings[0].id == "tls-handshake-failed"
    assert findings[0].severity == "high"


def test_deprecated_protocol_flagged():
    findings = check_tls(_tls(protocol_version="TLSv1.1"))
    assert any(f.id == "tls-deprecated-protocol" for f in findings)


def test_sslv3_is_critical():
    findings = check_tls(_tls(protocol_version="SSLv3"))
    match = next(f for f in findings if f.id == "tls-deprecated-protocol")
    assert match.severity == "critical"


def test_expired_certificate_is_critical():
    findings = check_tls(_tls(days_until_expiry=-5))
    match = next(f for f in findings if f.id == "tls-cert-expired")
    assert match.severity == "critical"


def test_expiring_within_two_weeks_is_high():
    findings = check_tls(_tls(days_until_expiry=10))
    match = next(f for f in findings if f.id == "tls-cert-expiring-soon")
    assert match.severity == "high"


def test_expiring_within_month_is_medium():
    findings = check_tls(_tls(days_until_expiry=25))
    match = next(f for f in findings if f.id == "tls-cert-expiring-within-month")
    assert match.severity == "medium"


def test_self_signed_detected():
    findings = check_tls(_tls(issuer="CN=example.com", subject="CN=example.com"))
    assert any(f.id == "tls-self-signed" for f in findings)
