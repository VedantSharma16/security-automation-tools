from datetime import datetime, timedelta, timezone

from webrecon.tls_check import TlsInfo, analyze_tls, inspect_tls

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_handshake_failure_yields_info_finding():
    info = TlsInfo(checked=False, error="connection refused")
    findings = analyze_tls(info, now=NOW)
    assert len(findings) == 1
    assert findings[0].id == "tls-check-failed"
    assert findings[0].severity == "info"


def test_weak_protocol_flagged_high():
    info = TlsInfo(checked=True, protocol="TLSv1.1", not_after=NOW + timedelta(days=200))
    findings = analyze_tls(info, now=NOW)
    ids = {f.id for f in findings}
    assert "tls-weak-protocol" in ids


def test_modern_protocol_not_flagged():
    info = TlsInfo(checked=True, protocol="TLSv1.3", not_after=NOW + timedelta(days=200))
    findings = analyze_tls(info, now=NOW)
    assert not any(f.id == "tls-weak-protocol" for f in findings)


def test_expired_cert_is_critical():
    info = TlsInfo(checked=True, protocol="TLSv1.3", not_after=NOW - timedelta(days=1))
    findings = analyze_tls(info, now=NOW)
    assert any(f.id == "tls-cert-expired" and f.severity == "critical" for f in findings)


def test_cert_expiring_soon_is_medium():
    info = TlsInfo(checked=True, protocol="TLSv1.3", not_after=NOW + timedelta(days=10))
    findings = analyze_tls(info, now=NOW)
    assert any(f.id == "tls-cert-expiring-soon" and f.severity == "medium" for f in findings)


def test_healthy_cert_raises_no_findings():
    info = TlsInfo(checked=True, protocol="TLSv1.3", not_after=NOW + timedelta(days=200))
    assert analyze_tls(info, now=NOW) == []


def test_inspect_tls_handles_unreachable_host_gracefully():
    # Port 1 on loopback is reserved/unlikely-to-listen -> fast connection refusal,
    # exercising the real (non-mocked) failure path without needing network access.
    info = inspect_tls("127.0.0.1", port=1, timeout=1.0)
    assert info.checked is False
    assert info.error
