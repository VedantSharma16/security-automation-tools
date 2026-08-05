from websecaudit.fetcher import TLSInfo
from websecaudit.tls import analyze_tls


def ids(findings):
    return {f.id for f in findings}


def test_no_tls_info_no_findings():
    assert analyze_tls(None) == []


def test_probe_error_flagged():
    findings = analyze_tls(TLSInfo(error="connection refused"))
    assert "tls-probe-failed" in ids(findings)


def test_deprecated_protocol_flagged_critical():
    findings = analyze_tls(TLSInfo(protocol_version="TLSv1.1"))
    matches = [f for f in findings if f.id == "deprecated-tls-protocol"]
    assert len(matches) == 1
    assert matches[0].severity == "critical"


def test_modern_protocol_not_flagged():
    findings = analyze_tls(TLSInfo(protocol_version="TLSv1.3"))
    assert "deprecated-tls-protocol" not in ids(findings)


def test_expired_certificate_flagged_critical():
    findings = analyze_tls(TLSInfo(protocol_version="TLSv1.3", days_until_expiry=-5))
    matches = [f for f in findings if f.id == "tls-certificate-expired"]
    assert len(matches) == 1
    assert matches[0].severity == "critical"


def test_certificate_expiring_within_two_weeks_flagged_high():
    findings = analyze_tls(TLSInfo(protocol_version="TLSv1.3", days_until_expiry=5))
    matches = [f for f in findings if f.id == "tls-certificate-expiring-soon"]
    assert len(matches) == 1
    assert matches[0].severity == "high"


def test_certificate_expiring_within_month_flagged_medium():
    findings = analyze_tls(TLSInfo(protocol_version="TLSv1.3", days_until_expiry=20))
    matches = [f for f in findings if f.id == "tls-certificate-expiring-soon"]
    assert len(matches) == 1
    assert matches[0].severity == "medium"


def test_healthy_certificate_no_findings():
    findings = analyze_tls(TLSInfo(protocol_version="TLSv1.3", days_until_expiry=200))
    assert findings == []
