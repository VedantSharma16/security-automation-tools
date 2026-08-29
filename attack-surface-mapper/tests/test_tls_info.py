import socket
import ssl
from datetime import datetime, timedelta, timezone

from asm import tls_info


def _cert_expiring_in(days: int) -> dict:
    not_after = datetime.now(timezone.utc) + timedelta(days=days)
    return {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
    }


def _fake_connect(cert: dict, protocol: str = "TLSv1.3"):
    def connect_fn(domain, port, timeout):
        return cert, protocol
    return connect_fn


def test_get_certificate_info_parses_cert_fields():
    connect_fn = _fake_connect(_cert_expiring_in(90))
    info = tls_info.get_certificate_info("example.com", connect_fn=connect_fn)
    assert info["subject"]["commonName"] == "example.com"
    assert info["issuer"]["organizationName"] == "Test CA"
    assert info["protocol"] == "TLSv1.3"
    assert 89 <= info["days_until_expiry"] <= 90


def test_get_certificate_info_returns_none_on_connection_failure():
    def connect_fn(domain, port, timeout):
        raise socket.timeout("timed out")

    assert tls_info.get_certificate_info("example.com", connect_fn=connect_fn) is None


def test_build_findings_none_info_is_medium():
    findings = tls_info.build_findings("example.com", None)
    assert len(findings) == 1
    assert findings[0].severity.name == "MEDIUM"


def test_build_findings_flags_expired_certificate():
    info = tls_info.get_certificate_info(
        "example.com", connect_fn=_fake_connect(_cert_expiring_in(-5))
    )
    findings = tls_info.build_findings("example.com", info)
    assert any(f.severity.name == "CRITICAL" for f in findings)


def test_build_findings_flags_imminent_expiry():
    info = tls_info.get_certificate_info(
        "example.com", connect_fn=_fake_connect(_cert_expiring_in(5))
    )
    findings = tls_info.build_findings("example.com", info)
    assert any(f.severity.name == "HIGH" and "expiring imminently" in f.title for f in findings)


def test_build_findings_flags_deprecated_protocol():
    info = tls_info.get_certificate_info(
        "example.com", connect_fn=_fake_connect(_cert_expiring_in(90), protocol="TLSv1.1")
    )
    findings = tls_info.build_findings("example.com", info)
    assert any(f.title == "Deprecated TLS protocol negotiated" for f in findings)


def test_build_findings_healthy_cert_only_produces_info_finding():
    info = tls_info.get_certificate_info(
        "example.com", connect_fn=_fake_connect(_cert_expiring_in(90))
    )
    findings = tls_info.build_findings("example.com", info)
    assert len(findings) == 1
    assert findings[0].severity.name == "INFO"
