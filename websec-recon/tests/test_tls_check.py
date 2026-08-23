import datetime as dt
import ssl

import pytest

from recon.tls_check import TLSCheckError, analyze_certificate, get_certificate_info


def make_probe(cert=None, protocol="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), raise_verify_error=False, raise_connect_error=False):
    def probe(host, port, timeout, verify):
        if raise_connect_error:
            raise OSError("connection refused")
        if verify and raise_verify_error:
            raise ssl.SSLCertVerificationError("certificate verify failed: self-signed certificate")
        return (cert if verify else None), protocol, cipher

    return probe


def test_get_certificate_info_trusted():
    cert = {"notAfter": "Jan  1 00:00:00 2030 GMT"}
    info = get_certificate_info("example.com", probe=make_probe(cert=cert))
    assert info["trusted"] is True
    assert info["protocol"] == "TLSv1.3"
    assert info["cipher"] == "TLS_AES_256_GCM_SHA384"


def test_get_certificate_info_untrusted_falls_back_to_unverified_probe():
    info = get_certificate_info("example.com", probe=make_probe(raise_verify_error=True))
    assert info["trusted"] is False
    assert "self-signed" in info["verification_error"]


def test_get_certificate_info_connect_failure_raises():
    with pytest.raises(TLSCheckError):
        get_certificate_info("example.com", probe=make_probe(raise_connect_error=True))


def test_analyze_certificate_flags_untrusted():
    info = {
        "host": "example.com",
        "port": 443,
        "trusted": False,
        "verification_error": "self-signed certificate",
        "cert": None,
        "protocol": "TLSv1.3",
        "cipher": "x",
    }
    findings = analyze_certificate(info)
    assert any(f.severity == "high" and "failed validation" in f.title for f in findings)


def test_analyze_certificate_flags_weak_protocol():
    info = {
        "host": "example.com",
        "port": 443,
        "trusted": True,
        "verification_error": None,
        "cert": {"notAfter": "Jan  1 00:00:00 2030 GMT"},
        "protocol": "TLSv1.1",
        "cipher": "x",
    }
    findings = analyze_certificate(info)
    assert any("Outdated TLS protocol" in f.title for f in findings)


def test_analyze_certificate_flags_expired():
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    info = {
        "host": "example.com",
        "port": 443,
        "trusted": True,
        "verification_error": None,
        "cert": {"notAfter": "Jan  1 00:00:00 2025 GMT"},
        "protocol": "TLSv1.3",
        "cipher": "x",
    }
    findings = analyze_certificate(info, now=now)
    critical = [f for f in findings if f.severity == "critical"]
    assert len(critical) == 1
    assert "expired" in critical[0].title.lower()


def test_analyze_certificate_flags_expiring_soon():
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    info = {
        "host": "example.com",
        "port": 443,
        "trusted": True,
        "verification_error": None,
        "cert": {"notAfter": "Jan  10 00:00:00 2026 GMT"},
        "protocol": "TLSv1.3",
        "cipher": "x",
    }
    findings = analyze_certificate(info, now=now)
    assert any("expiring soon" in f.title.lower() for f in findings)


def test_analyze_certificate_healthy_cert_no_findings():
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    info = {
        "host": "example.com",
        "port": 443,
        "trusted": True,
        "verification_error": None,
        "cert": {"notAfter": "Jan  1 00:00:00 2027 GMT"},
        "protocol": "TLSv1.3",
        "cipher": "x",
    }
    findings = analyze_certificate(info, now=now)
    assert findings == []
