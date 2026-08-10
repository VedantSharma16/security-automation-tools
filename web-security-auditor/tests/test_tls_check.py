import socket
import ssl
from datetime import datetime, timedelta, timezone

import pytest

from webauditor import tls_check
from webauditor.findings import Severity
from webauditor.tls_check import CertificateInfo, check_tls, evaluate_certificate


def make_info(days_until_expiry=200, protocol="TLSv1.3"):
    return CertificateInfo(
        subject="CN=example.com",
        issuer="CN=Example CA",
        not_after=datetime.now(timezone.utc) + timedelta(days=days_until_expiry),
        protocol=protocol,
        days_until_expiry=days_until_expiry,
    )


def test_healthy_certificate_has_no_findings():
    findings = evaluate_certificate(make_info(days_until_expiry=200, protocol="TLSv1.3"))
    assert findings == []


def test_expired_certificate_is_critical():
    findings = evaluate_certificate(make_info(days_until_expiry=-5))
    assert len(findings) == 1
    assert findings[0].id == "TLS-CERT-EXPIRED"
    assert findings[0].severity == Severity.CRITICAL


def test_expiring_soon_certificate_is_medium():
    findings = evaluate_certificate(make_info(days_until_expiry=10))
    assert len(findings) == 1
    assert findings[0].id == "TLS-CERT-EXPIRING-SOON"
    assert findings[0].severity == Severity.MEDIUM


def test_certificate_just_outside_warning_window_has_no_expiry_finding():
    findings = evaluate_certificate(make_info(days_until_expiry=31))
    assert findings == []


@pytest.mark.parametrize("protocol", ["SSLv3", "TLSv1", "TLSv1.1"])
def test_weak_protocol_flagged_high(protocol):
    findings = evaluate_certificate(make_info(protocol=protocol))
    weak = [f for f in findings if f.id == "TLS-WEAK-PROTOCOL"]
    assert len(weak) == 1
    assert weak[0].severity == Severity.HIGH


def test_modern_protocol_not_flagged():
    findings = evaluate_certificate(make_info(protocol="TLSv1.3"))
    assert not any(f.id == "TLS-WEAK-PROTOCOL" for f in findings)


def test_expired_and_weak_protocol_both_reported():
    findings = evaluate_certificate(make_info(days_until_expiry=-1, protocol="TLSv1"))
    ids = {f.id for f in findings}
    assert ids == {"TLS-CERT-EXPIRED", "TLS-WEAK-PROTOCOL"}


def test_check_tls_reports_connection_failure_as_info(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr(tls_check, "get_certificate_info", raise_timeout)

    findings = check_tls("unreachable.example")
    assert len(findings) == 1
    assert findings[0].id == "TLS-CONNECT-FAILED"
    assert findings[0].severity == Severity.INFO


def test_check_tls_reports_ssl_error_as_info(monkeypatch):
    def raise_ssl_error(*args, **kwargs):
        raise ssl.SSLError("handshake failure")

    monkeypatch.setattr(tls_check, "get_certificate_info", raise_ssl_error)

    findings = check_tls("badssl.example")
    assert findings[0].id == "TLS-CONNECT-FAILED"


def test_check_tls_delegates_to_evaluate_certificate(monkeypatch):
    monkeypatch.setattr(tls_check, "get_certificate_info", lambda *a, **k: make_info(days_until_expiry=-1))
    findings = check_tls("example.com")
    assert findings[0].id == "TLS-CERT-EXPIRED"
