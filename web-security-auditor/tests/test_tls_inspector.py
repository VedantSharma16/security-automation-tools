import datetime
import socket
import ssl
from contextlib import contextmanager
from unittest import mock

from webauditor import tls_inspector
from webauditor.models import Severity, Status
from webauditor.tls_inspector import TLSInfo, evaluate_tls, inspect


def _cert_not_after(days_from_now: int) -> str:
    when = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_from_now)
    return when.strftime("%b %d %H:%M:%S %Y GMT")


class _FakeTLSSocket:
    def __init__(self, cert, protocol, cipher_name):
        self._cert = cert
        self._protocol = protocol
        self._cipher_name = cipher_name

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def getpeercert(self):
        return self._cert

    def version(self):
        return self._protocol

    def cipher(self):
        return (self._cipher_name, "TLSv1.3", 128)


class _FakeContext:
    def __init__(self, tls_socket):
        self._tls_socket = tls_socket

    def wrap_socket(self, sock, server_hostname=None):
        return self._tls_socket


@contextmanager
def _fake_plain_socket():
    yield mock.MagicMock()


def _patch_handshake(monkeypatch, tls_socket):
    monkeypatch.setattr(tls_inspector.socket, "create_connection", lambda *a, **k: _fake_plain_socket())
    monkeypatch.setattr(tls_inspector.ssl, "create_default_context", lambda: _FakeContext(tls_socket))


def test_inspect_reports_protocol_cipher_and_expiry(monkeypatch):
    cert = {
        "notAfter": _cert_not_after(90),
        "issuer": ((("organizationName", "Example CA"),),),
        "subject": ((("commonName", "example.com"),),),
    }
    tls_socket = _FakeTLSSocket(cert, "TLSv1.3", "TLS_AES_256_GCM_SHA384")
    _patch_handshake(monkeypatch, tls_socket)

    info = inspect("example.com", 443)

    assert info.ok
    assert info.protocol == "TLSv1.3"
    assert info.cipher == "TLS_AES_256_GCM_SHA384"
    assert info.issuer == "organizationName=Example CA"
    assert info.subject == "commonName=example.com"
    assert 88 <= info.days_until_expiry <= 90


def test_inspect_handles_connection_failure(monkeypatch):
    def _raise(*a, **k):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(tls_inspector.socket, "create_connection", _raise)

    info = inspect("nonexistent.invalid", 443)

    assert not info.ok
    assert "Name or service" in info.error


def test_evaluate_tls_flags_weak_protocol():
    info = TLSInfo(host="example.com", port=443, protocol="TLSv1.1", cipher="AES128-SHA", days_until_expiry=200, not_after="irrelevant")
    findings = evaluate_tls(info)
    protocol_finding = next(f for f in findings if f.check_id == "tls-protocol")
    assert protocol_finding.status == Status.FAIL
    assert protocol_finding.severity == Severity.CRITICAL


def test_evaluate_tls_flags_expired_certificate():
    info = TLSInfo(host="example.com", port=443, protocol="TLSv1.3", cipher="X", days_until_expiry=-5, not_after="irrelevant")
    findings = evaluate_tls(info)
    expiry_finding = next(f for f in findings if f.check_id == "tls-expiry")
    assert expiry_finding.status == Status.FAIL
    assert expiry_finding.severity == Severity.CRITICAL


def test_evaluate_tls_warns_on_soon_expiry():
    info = TLSInfo(host="example.com", port=443, protocol="TLSv1.3", cipher="X", days_until_expiry=20, not_after="irrelevant")
    findings = evaluate_tls(info)
    expiry_finding = next(f for f in findings if f.check_id == "tls-expiry")
    assert expiry_finding.status == Status.WARN
    assert expiry_finding.severity == Severity.MEDIUM


def test_evaluate_tls_passes_healthy_cert():
    info = TLSInfo(host="example.com", port=443, protocol="TLSv1.3", cipher="X", days_until_expiry=200, not_after="irrelevant")
    findings = evaluate_tls(info)
    assert all(f.status == Status.PASS for f in findings)


def test_evaluate_tls_reports_handshake_failure_as_single_finding():
    info = TLSInfo(host="example.com", port=443, error="connection refused")
    findings = evaluate_tls(info)
    assert len(findings) == 1
    assert findings[0].check_id == "tls-handshake"
    assert findings[0].status == Status.FAIL
