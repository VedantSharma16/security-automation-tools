import datetime

from recon_agent.tools import tls_tool


def cert_date(delta_days: int) -> str:
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=delta_days)
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


def make_raw_cert(not_after: str, protocol: str = "TLSv1.3"):
    return {
        "cert": {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Test CA"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": not_after,
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        },
        "protocol": protocol,
    }


def test_run_reports_healthy_certificate():
    raw = make_raw_cert(cert_date(90))
    result = tls_tool.run("example.com", connect_fn=lambda h, p: raw)
    assert result.tool == "tls"
    assert result.data["san"] == ["example.com", "www.example.com"]
    assert result.data["days_remaining"] in (89, 90)
    assert result.findings == []


def test_analyze_cert_flags_expired_certificate_as_critical():
    info = {"days_remaining": -5, "protocol": "TLSv1.3"}
    findings = tls_tool.analyze_cert(info)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "expired" in findings[0].title.lower()


def test_analyze_cert_flags_certificate_expiring_very_soon_as_high():
    info = {"days_remaining": 5, "protocol": "TLSv1.3"}
    findings = tls_tool.analyze_cert(info)
    assert findings[0].severity == "high"


def test_analyze_cert_flags_certificate_expiring_soon_as_medium():
    info = {"days_remaining": 20, "protocol": "TLSv1.3"}
    findings = tls_tool.analyze_cert(info)
    assert findings[0].severity == "medium"


def test_analyze_cert_flags_weak_protocol():
    info = {"days_remaining": 200, "protocol": "TLSv1.1"}
    findings = tls_tool.analyze_cert(info)
    titles = {f.title for f in findings}
    assert "Weak TLS protocol negotiated" in titles


def test_run_handles_handshake_failure_gracefully():
    def broken_connect(hostname, port):
        raise OSError("connection reset")

    result = tls_tool.run("example.com", connect_fn=broken_connect)
    assert result.data["error"] == "connection reset"
    assert result.findings[0].title == "TLS handshake failed"
    assert result.findings[0].severity == "high"
