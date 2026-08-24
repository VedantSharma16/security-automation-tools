from datetime import datetime, timedelta, timezone

from webauditor.tls import check_tls

_CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def _cert_expiring_in(days: int) -> str:
    expiry = datetime.now(timezone.utc) + timedelta(days=days)
    return expiry.strftime(_CERT_DATE_FORMAT)


def test_healthy_tls_produces_no_findings():
    def fake_tls_info(hostname, port):
        return {
            "cert": {"notAfter": _cert_expiring_in(200)},
            "protocol": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

    findings = check_tls("example.com", 443, tls_info_fn=fake_tls_info)
    assert findings == []


def test_outdated_protocol_flagged_high():
    def fake_tls_info(hostname, port):
        return {"cert": {}, "protocol": "TLSv1.1", "cipher": ("ECDHE-RSA-AES128-SHA", "TLSv1.1", 128)}

    findings = check_tls("example.com", 443, tls_info_fn=fake_tls_info)
    assert any(f.id == "tls-outdated-protocol" and f.severity.name == "HIGH" for f in findings)


def test_weak_cipher_flagged_critical():
    def fake_tls_info(hostname, port):
        return {"cert": {}, "protocol": "TLSv1.2", "cipher": ("RC4-MD5", "TLSv1.2", 128)}

    findings = check_tls("example.com", 443, tls_info_fn=fake_tls_info)
    assert any(f.id == "tls-weak-cipher" and f.severity.name == "CRITICAL" for f in findings)


def test_expired_certificate_flagged_critical():
    def fake_tls_info(hostname, port):
        return {
            "cert": {"notAfter": _cert_expiring_in(-5)},
            "protocol": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

    findings = check_tls("example.com", 443, tls_info_fn=fake_tls_info)
    assert any(f.id == "tls-cert-expired" and f.severity.name == "CRITICAL" for f in findings)


def test_certificate_expiring_soon_flagged_medium():
    def fake_tls_info(hostname, port):
        return {
            "cert": {"notAfter": _cert_expiring_in(10)},
            "protocol": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

    findings = check_tls("example.com", 443, tls_info_fn=fake_tls_info)
    assert any(f.id == "tls-cert-expiring-soon" and f.severity.name == "MEDIUM" for f in findings)


def test_connection_failure_produces_informational_finding():
    def failing_tls_info(hostname, port):
        raise ConnectionRefusedError("connection refused")

    findings = check_tls("example.com", 443, tls_info_fn=failing_tls_info)
    assert len(findings) == 1
    assert findings[0].id == "tls-connection-failed"
    assert findings[0].severity.name == "INFO"
