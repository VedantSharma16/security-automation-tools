from recon_agent.models import TLSResult
from recon_agent.tls_analyzer import analyze_tls


def _tls(**overrides):
    kwargs = dict(host="example.com", port=443, ok=True, version="TLSv1.3", days_until_expiry=200)
    kwargs.update(overrides)
    return TLSResult(**kwargs)


def test_failed_handshake_has_no_findings():
    assert analyze_tls(_tls(ok=False, version=None, days_until_expiry=None)) == []


def test_modern_tls_with_healthy_cert_has_no_findings():
    assert analyze_tls(_tls()) == []


def test_weak_protocol_version_flagged():
    findings = [f for f in analyze_tls(_tls(version="TLSv1.1")) if f.id == "tls-weak-protocol-version"]
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_tls_1_2_is_not_flagged_as_weak():
    findings = [f for f in analyze_tls(_tls(version="TLSv1.2")) if f.id == "tls-weak-protocol-version"]
    assert findings == []


def test_expired_certificate_is_critical():
    findings = [f for f in analyze_tls(_tls(days_until_expiry=-5)) if f.id == "tls-certificate-expired"]
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_certificate_expiring_within_a_week_is_high():
    findings = [f for f in analyze_tls(_tls(days_until_expiry=3)) if f.id == "tls-certificate-expiring-soon"]
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_certificate_expiring_within_a_month_is_medium():
    findings = [f for f in analyze_tls(_tls(days_until_expiry=25)) if f.id == "tls-certificate-expiring-soon"]
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_certificate_with_plenty_of_life_not_flagged():
    findings = [f for f in analyze_tls(_tls(days_until_expiry=200)) if f.id == "tls-certificate-expiring-soon"]
    assert findings == []


def test_no_expiry_data_does_not_crash():
    assert analyze_tls(_tls(days_until_expiry=None)) == []
