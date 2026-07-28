from datetime import datetime, timedelta, timezone

from attack_surface_mapper import tlsaudit


def _cert_expiring_in(days: int, now: datetime) -> dict:
    expiry = now + timedelta(days=days)
    return {"notAfter": expiry.strftime(tlsaudit._CERT_DATE_FORMAT)}


def test_check_expiry_flags_expired_cert_as_critical():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert = _cert_expiring_in(-5, now)
    findings = tlsaudit.check_expiry(cert, now=now)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "expired" in findings[0].title.lower()


def test_check_expiry_flags_imminent_expiry_as_high():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert = _cert_expiring_in(3, now)
    findings = tlsaudit.check_expiry(cert, now=now)
    assert findings[0].severity == "high"


def test_check_expiry_flags_soon_expiry_as_medium():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert = _cert_expiring_in(20, now)
    findings = tlsaudit.check_expiry(cert, now=now, warn_days=30)
    assert findings[0].severity == "medium"


def test_check_expiry_healthy_cert_has_no_findings():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert = _cert_expiring_in(200, now)
    assert tlsaudit.check_expiry(cert, now=now) == []


def test_check_expiry_missing_cert_is_medium():
    findings = tlsaudit.check_expiry(None)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_check_expiry_unparseable_date_is_low():
    findings = tlsaudit.check_expiry({"notAfter": "not-a-date"})
    assert findings[0].severity == "low"


def test_get_certificate_returns_none_on_failure(monkeypatch):
    import socket

    def raise_error(*args, **kwargs):
        raise OSError("refused")

    monkeypatch.setattr(socket, "create_connection", raise_error)
    assert tlsaudit.get_certificate("example.com") is None
