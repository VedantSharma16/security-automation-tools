from recon_agent.agent import ReconRun, ReconSession
from recon_agent.report import build_report


def _run_with_steps(steps: dict) -> ReconRun:
    session = ReconSession(target="example.com")
    for tool, data in steps.items():
        session.record(tool, data)
    return ReconRun(session=session, trace=[], planner_live=False)


def test_dns_failure_produces_high_severity_finding():
    run = _run_with_steps({"dns_lookup": {"resolved": False, "error": "NXDOMAIN"}})
    report = build_report(run)
    assert any(f.category == "dns" and f.severity == "high" for f in report.findings)


def test_open_high_risk_port_is_flagged():
    run = _run_with_steps(
        {
            "dns_lookup": {"resolved": True, "ip": "1.2.3.4"},
            "port_scan": {"ip": "1.2.3.4", "open_ports": [{"port": 3389, "open": True, "banner": None}]},
        }
    )
    report = build_report(run)
    port_findings = [f for f in report.findings if f.category == "open-port"]
    assert len(port_findings) == 1
    assert port_findings[0].severity == "critical"
    assert "3389" in port_findings[0].title


def test_unknown_open_port_defaults_to_medium():
    run = _run_with_steps(
        {
            "dns_lookup": {"resolved": True, "ip": "1.2.3.4"},
            "port_scan": {"ip": "1.2.3.4", "open_ports": [{"port": 31337, "open": True, "banner": None}]},
        }
    )
    report = build_report(run)
    assert report.findings[0].severity == "medium"


def test_missing_headers_generate_findings():
    run = _run_with_steps(
        {
            "dns_lookup": {"resolved": True, "ip": "1.2.3.4"},
            "http_headers": {"status": 200, "headers": {}, "error": None},
        }
    )
    report = build_report(run)
    header_findings = [f for f in report.findings if f.category == "http-header"]
    assert len(header_findings) >= 5


def test_expired_certificate_is_critical():
    run = _run_with_steps(
        {
            "dns_lookup": {"resolved": True, "ip": "1.2.3.4"},
            "tls_cert": {"fetched": True, "not_after": "Jan 1 00:00:00 2020 GMT", "days_remaining": -400, "issuer": "Test CA", "error": None},
        }
    )
    report = build_report(run)
    tls_findings = [f for f in report.findings if f.category == "tls"]
    assert tls_findings[0].severity == "critical"


def test_healthy_target_scores_zero_and_info_severity():
    run = _run_with_steps(
        {
            "dns_lookup": {"resolved": True, "ip": "1.2.3.4"},
            "port_scan": {"ip": "1.2.3.4", "open_ports": []},
            "http_headers": {
                "status": 200,
                "error": None,
                "headers": {
                    "strict-transport-security": "max-age=1",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "no-referrer",
                    "permissions-policy": "geolocation=()",
                },
            },
            "tls_cert": {"fetched": True, "not_after": "Jan 1 00:00:00 2035 GMT", "days_remaining": 3000, "issuer": "Test CA", "error": None},
        }
    )
    report = build_report(run)
    assert report.findings == []
    assert report.risk_score == 0
    assert report.overall_severity == "info"


def test_risk_score_capped_at_100():
    many_high_ports = {"ip": "1.2.3.4", "open_ports": [{"port": 3389, "open": True, "banner": None} for _ in range(20)]}
    run = _run_with_steps({"dns_lookup": {"resolved": True, "ip": "1.2.3.4"}, "port_scan": many_high_ports})
    report = build_report(run)
    assert report.risk_score == 100
