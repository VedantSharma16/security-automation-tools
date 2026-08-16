from datetime import datetime, timedelta, timezone

import pytest

from webrecon.tls_check import inspect_certificate, parse_cert_date

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_cert(not_before="Jan  1 00:00:00 2025 GMT", not_after="Jan  1 00:00:00 2027 GMT", subject_cn="example.com", issuer_cn="Some CA"):
    return {
        "notBefore": not_before,
        "notAfter": not_after,
        "subject": ((("commonName", subject_cn),),),
        "issuer": ((("commonName", issuer_cn),),),
    }


def test_parse_cert_date():
    dt = parse_cert_date("Jan  1 00:00:00 2027 GMT")
    assert dt.year == 2027
    assert dt.tzinfo is not None


def test_healthy_certificate_has_no_findings_besides_info():
    report = inspect_certificate(make_cert(), "TLSv1.3", now=NOW)
    assert [f.severity for f in report.findings] == ["info"]
    assert report.subject_cn == "example.com"
    assert report.issuer_cn == "Some CA"


def test_expired_certificate_flagged_critical():
    cert = make_cert(not_after="Jan  1 00:00:00 2025 GMT")
    report = inspect_certificate(cert, "TLSv1.3", now=NOW)
    severities = [f.severity for f in report.findings]
    assert "critical" in severities
    assert report.days_until_expiry < 0


def test_certificate_expiring_soon_flagged_high():
    soon = NOW + timedelta(days=10)
    cert = make_cert(not_after=soon.strftime("%b %d %H:%M:%S %Y GMT"))
    report = inspect_certificate(cert, "TLSv1.3", now=NOW)
    assert any(f.severity == "high" for f in report.findings)


def test_self_signed_certificate_flagged_medium():
    cert = make_cert(subject_cn="example.com", issuer_cn="example.com")
    report = inspect_certificate(cert, "TLSv1.3", now=NOW)
    assert any(f.severity == "medium" and "self-signed" in f.message for f in report.findings)


def test_weak_protocol_flagged_critical():
    report = inspect_certificate(make_cert(), "TLSv1.1", now=NOW)
    assert any(f.severity == "critical" and "TLSv1.1" in f.message for f in report.findings)


def test_not_yet_valid_certificate_flagged_high():
    cert = make_cert(not_before="Jan  1 00:00:00 2027 GMT", not_after="Jan  1 00:00:00 2028 GMT")
    report = inspect_certificate(cert, "TLSv1.3", now=NOW)
    assert any(f.severity == "high" and "not yet valid" in f.message for f in report.findings)
