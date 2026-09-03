from recon_agent.findings import SEVERITY_ORDER, Finding, evaluate, overall_risk
from recon_agent.http_fingerprint import HttpFingerprint
from recon_agent.port_scan import PortResult

FULL_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


def test_risky_port_flagged_critical():
    ports = [PortResult(port=6379, open=True, service="redis")]
    findings = evaluate("host", ports, [])
    assert any(f.category == "exposed-service" and f.severity == "critical" for f in findings)


def test_boring_port_not_flagged():
    ports = [PortResult(port=443, open=True, service="https")]
    findings = evaluate("host", ports, [])
    assert not any(f.category == "exposed-service" for f in findings)


def test_sensitive_title_flagged():
    fp = HttpFingerprint(port=443, scheme="https", status=200, headers=FULL_HEADERS, title="Jenkins Dashboard")
    findings = evaluate("host", [], [fp])
    assert any(f.category == "sensitive-endpoint" for f in findings)


def test_missing_security_headers_flagged():
    fp = HttpFingerprint(port=443, scheme="https", status=200, headers={})
    findings = evaluate("host", [], [fp])
    assert any(f.category == "missing-security-headers" for f in findings)


def test_complete_security_headers_not_flagged():
    fp = HttpFingerprint(port=443, scheme="https", status=200, headers=FULL_HEADERS)
    findings = evaluate("host", [], [fp])
    assert not any(f.category == "missing-security-headers" for f in findings)


def test_expiring_cert_flagged_medium():
    fp = HttpFingerprint(port=443, scheme="https", status=200, headers=FULL_HEADERS, tls_days_remaining=5)
    findings = evaluate("host", [], [fp])
    match = [f for f in findings if f.category == "expiring-certificate"]
    assert match and match[0].severity == "medium"


def test_expired_cert_flagged_critical():
    fp = HttpFingerprint(port=443, scheme="https", status=200, headers=FULL_HEADERS, tls_days_remaining=-3)
    findings = evaluate("host", [], [fp])
    match = [f for f in findings if f.category == "expired-certificate"]
    assert match and match[0].severity == "critical"


def test_unverifiable_cert_flagged():
    fp = HttpFingerprint(port=443, scheme="https", status=200, headers=FULL_HEADERS, tls_error="self-signed certificate")
    findings = evaluate("host", [], [fp])
    assert any(f.category == "unverifiable-certificate" for f in findings)


def test_cleartext_http_flagged():
    fp = HttpFingerprint(port=80, scheme="http", status=200, headers={})
    findings = evaluate("host", [], [fp])
    assert any(f.category == "cleartext-http" for f in findings)


def test_fingerprint_with_error_is_skipped():
    fp = HttpFingerprint(port=80, scheme="http", error="connection refused")
    findings = evaluate("host", [], [fp])
    assert findings == []


def test_overall_risk_empty_is_info():
    assert overall_risk([]) == "info"


def test_overall_risk_takes_highest_severity():
    findings = [Finding("low", "x", "t", "d"), Finding("critical", "y", "t", "d")]
    assert overall_risk(findings) == "critical"


def test_findings_sorted_most_severe_first():
    ports = [PortResult(port=6379, open=True, service="redis"), PortResult(port=445, open=True, service="smb")]
    findings = evaluate("host", ports, [])
    ranks = [SEVERITY_ORDER.index(f.severity) for f in findings]
    assert ranks == sorted(ranks, reverse=True)
