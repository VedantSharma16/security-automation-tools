from datetime import datetime, timedelta, timezone

from webaudit import tls


def test_handshake_error_reports_single_fail():
    results = tls.analyze_tls(protocol=None, not_after=None, error="certificate verify failed")
    assert len(results) == 1
    assert results[0].status == "fail"
    assert "handshake" in results[0].id


def test_weak_protocol_fails():
    results = tls.analyze_tls(protocol="TLSv1.1", not_after=None, error=None)
    protocol_result = next(r for r in results if r.id == "tls-protocol")
    assert protocol_result.status == "fail"


def test_modern_protocol_passes():
    results = tls.analyze_tls(protocol="TLSv1.3", not_after=None, error=None)
    protocol_result = next(r for r in results if r.id == "tls-protocol")
    assert protocol_result.status == "pass"


def test_expired_certificate_is_critical():
    expired = datetime.now(timezone.utc) - timedelta(days=5)
    results = tls.analyze_tls(protocol="TLSv1.3", not_after=expired, error=None)
    expiry_result = next(r for r in results if r.id == "tls-expiry")
    assert expiry_result.status == "fail"
    assert expiry_result.severity == "critical"


def test_certificate_expiring_soon_fails_high():
    soon = datetime.now(timezone.utc) + timedelta(days=5)
    results = tls.analyze_tls(protocol="TLSv1.3", not_after=soon, error=None)
    expiry_result = next(r for r in results if r.id == "tls-expiry")
    assert expiry_result.status == "fail"
    assert expiry_result.severity == "high"


def test_certificate_expiring_within_a_month_warns():
    within_month = datetime.now(timezone.utc) + timedelta(days=25)
    results = tls.analyze_tls(protocol="TLSv1.3", not_after=within_month, error=None)
    expiry_result = next(r for r in results if r.id == "tls-expiry")
    assert expiry_result.status == "warn"


def test_healthy_certificate_passes():
    healthy = datetime.now(timezone.utc) + timedelta(days=200)
    results = tls.analyze_tls(protocol="TLSv1.3", not_after=healthy, error=None)
    expiry_result = next(r for r in results if r.id == "tls-expiry")
    assert expiry_result.status == "pass"
