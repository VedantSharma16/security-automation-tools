from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from recon_agent import tls_recon


def _make_der_cert(
    common_name: str,
    not_before: datetime,
    not_after: datetime,
    sans: list[str] | None = None,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(encoding=serialization.Encoding.DER)


class FakeConn:
    def __init__(self, der_cert, protocol="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384"):
        self._der_cert = der_cert
        self._protocol = protocol
        self._cipher_name = cipher_name
        self.closed = False

    def getpeercert(self, binary_form=False):
        assert binary_form is True
        return self._der_cert

    def version(self):
        return self._protocol

    def cipher(self):
        return (self._cipher_name, "TLSv1.3", 256)

    def close(self):
        self.closed = True


def _future(days: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)


def _past(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def test_check_tls_healthy_certificate():
    der = _make_der_cert("example.com", _past(10), _future(200), sans=["example.com", "www.example.com"])
    connect = lambda host, port, timeout: FakeConn(der)

    finding = tls_recon.check_tls("example.com", connect=connect)

    assert finding.connected
    assert "example.com" in finding.subject
    assert finding.subject_alt_names == ["example.com", "www.example.com"]
    assert finding.issues == []


def test_check_tls_flags_expired_certificate():
    der = _make_der_cert("example.com", _past(400), _past(5))
    connect = lambda host, port, timeout: FakeConn(der)

    finding = tls_recon.check_tls("example.com", connect=connect)

    assert finding.days_until_expiry < 0
    assert any("expired" in issue for issue in finding.issues)


def test_check_tls_flags_expiring_soon():
    der = _make_der_cert("example.com", _past(10), _future(5))
    connect = lambda host, port, timeout: FakeConn(der)

    finding = tls_recon.check_tls("example.com", connect=connect)

    assert any("expires in" in issue for issue in finding.issues)


def test_check_tls_flags_weak_protocol():
    der = _make_der_cert("example.com", _past(10), _future(200))
    connect = lambda host, port, timeout: FakeConn(der, protocol="TLSv1.1")

    finding = tls_recon.check_tls("example.com", connect=connect)

    assert any("Weak/deprecated protocol" in issue for issue in finding.issues)


def test_check_tls_handles_connection_failure():
    def connect(host, port, timeout):
        raise OSError("connection refused")

    finding = tls_recon.check_tls("unreachable.example", connect=connect)

    assert not finding.connected
    assert "connection refused" in finding.error


def test_check_tls_handles_missing_certificate():
    connect = lambda host, port, timeout: FakeConn(None)

    finding = tls_recon.check_tls("example.com", connect=connect)

    assert finding.connected
    assert "No certificate returned by peer" in finding.issues
