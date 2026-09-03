from recon_agent.agent import ReconRun
from recon_agent.findings import Finding
from recon_agent.http_fingerprint import HttpFingerprint
from recon_agent.port_scan import PortResult
from recon_agent.report import build_report, render_console


def make_run():
    run = ReconRun(target="example.com")
    run.ip = "1.2.3.4"
    run.subdomains = {"www.example.com": "1.1.1.1"}
    run.open_ports = [PortResult(port=6379, open=True, service="redis")]
    run.http_fingerprints = [HttpFingerprint(port=443, scheme="https", status=200)]
    run.tool_calls_made = ["resolve_and_enumerate_subdomains", "scan_ports"]
    run.agent_narrative = "test narrative"
    return run


def test_build_report_computes_overall_risk_from_findings():
    findings = [Finding("critical", "exposed-service", "example.com:6379", "redis open")]
    report = build_report(make_run(), findings)
    assert report["overall_risk"] == "critical"
    assert report["findings"][0]["category"] == "exposed-service"
    assert report["ip"] == "1.2.3.4"


def test_build_report_no_findings_is_info_risk():
    report = build_report(make_run(), [])
    assert report["overall_risk"] == "info"
    assert report["findings"] == []


def test_render_console_includes_key_sections_without_color():
    findings = [Finding("critical", "exposed-service", "example.com:6379", "redis open")]
    report = build_report(make_run(), findings)
    output = render_console(report, use_color=False)

    assert "Overall risk: CRITICAL" in output
    assert "example.com" in output
    assert "www.example.com -> 1.1.1.1" in output
    assert "6379/tcp (redis)" in output
    assert "redis open" in output
    assert "test narrative" in output
    assert "\033[" not in output


def test_render_console_no_findings_message():
    report = build_report(make_run(), [])
    output = render_console(report, use_color=False)
    assert "No findings." in output
