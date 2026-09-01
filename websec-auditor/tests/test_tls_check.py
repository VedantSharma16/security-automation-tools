from datetime import datetime, timedelta, timezone

from websec_auditor.tls_check import TLSInfo, analyze_tls, fetch_tls_info


def make_info(**overrides):
    defaults = dict(
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        not_after=datetime.now(timezone.utc) + timedelta(days=200),
        not_before=datetime.now(timezone.utc) - timedelta(days=10),
        issuer="CN=Test CA",
        subject="CN=example.com",
        san=["example.com"],
    )
    defaults.update(overrides)
    return TLSInfo(**defaults)


def find(findings, finding_id):
    return next((f for f in findings if f.id == finding_id), None)


def test_healthy_cert_and_modern_protocol_produce_no_findings():
    info = make_info()
    assert analyze_tls(info) == []


def test_weak_protocol_flagged_critical():
    info = make_info(protocol="TLSv1.1")
    findings = analyze_tls(info)
    finding = find(findings, "weak-tls-protocol")
    assert finding is not None
    assert finding.severity == "critical"


def test_expired_certificate_flagged():
    info = make_info(not_after=datetime.now(timezone.utc) - timedelta(days=5))
    findings = analyze_tls(info)
    finding = find(findings, "cert-expired")
    assert finding is not None
    assert finding.severity == "critical"


def test_certificate_expiring_soon_flagged_medium():
    info = make_info(not_after=datetime.now(timezone.utc) + timedelta(days=10))
    findings = analyze_tls(info)
    finding = find(findings, "cert-expiring-soon")
    assert finding is not None
    assert finding.severity == "medium"


def test_certificate_far_from_expiry_not_flagged():
    info = make_info(not_after=datetime.now(timezone.utc) + timedelta(days=100))
    findings = analyze_tls(info)
    assert find(findings, "cert-expiring-soon") is None


def test_handshake_failure_reported_as_finding():
    info = TLSInfo(
        protocol=None, cipher=None, not_after=None, not_before=None,
        issuer=None, subject=None, san=[], error="connection refused",
    )
    findings = analyze_tls(info)
    finding = find(findings, "tls-handshake-failed")
    assert finding is not None
    assert finding.severity == "high"


def test_fetch_tls_info_uses_injected_connector():
    called_with = {}

    def fake_connector(hostname, port, timeout):
        called_with["args"] = (hostname, port, timeout)
        return make_info()

    info = fetch_tls_info("example.com", 443, timeout=3.0, connector=fake_connector)
    assert called_with["args"] == ("example.com", 443, 3.0)
    assert info.protocol == "TLSv1.3"
