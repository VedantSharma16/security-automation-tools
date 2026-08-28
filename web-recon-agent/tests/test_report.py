from datetime import datetime, timedelta, timezone

from recon_agent.agent import AgentRun, TranscriptStep
from recon_agent.llm_client import Narrator
from recon_agent.planner import AgentAction
from recon_agent.report import Finding, build_report, collect_findings, overall_severity
from recon_agent.tools import ToolResult


def _step(index, tool, ok=True, data=None, error=None):
    return TranscriptStep(index, AgentAction(tool, {}, ""), ToolResult(tool, ok, data or {}, error))


def test_collect_findings_flags_missing_security_headers():
    run = AgentRun(
        "https://example.com",
        [
            _step(0, "fetch_headers", data={"url": "https://example.com", "status": 200, "headers": {}}),
            _step(
                1,
                "grade_security_headers",
                data={
                    "score": 25,
                    "missing": [{"header": "Content-Security-Policy", "severity": "high", "advice": "add CSP"}],
                    "present": [],
                    "info_disclosure": [],
                    "scheme": "https",
                },
            ),
        ],
        "done",
        "DeterministicPlanner",
    )
    findings = collect_findings(run)
    assert any(f.category == "security_headers" and f.severity == "high" for f in findings)


def test_collect_findings_flags_unexpected_open_port():
    run = AgentRun(
        "https://example.com",
        [_step(0, "port_scan", data={"host": "example.com", "scanned": [22, 80, 443], "open_ports": [22, 443]})],
        "done",
        "DeterministicPlanner",
    )
    findings = collect_findings(run)
    assert any("22" in f.summary for f in findings)
    assert not any("443" in f.summary for f in findings)


def test_collect_findings_flags_sensitive_robots_path():
    run = AgentRun(
        "https://example.com",
        [
            _step(
                0,
                "fetch_robots_txt",
                data={"url": "https://example.com/robots.txt", "status": 200, "disallowed_paths": ["/admin/", "/public"]},
            )
        ],
        "done",
        "DeterministicPlanner",
    )
    findings = collect_findings(run)
    assert any(f.category == "recon_disclosure" and f.severity == "medium" for f in findings)


def test_collect_findings_flags_outdated_tls():
    run = AgentRun(
        "https://example.com",
        [_step(0, "check_tls", data={"host": "example.com", "port": 443, "protocol": "TLSv1.1", "cipher": "x", "cert": {}})],
        "done",
        "DeterministicPlanner",
    )
    findings = collect_findings(run)
    assert any(f.category == "tls" and f.severity == "high" for f in findings)


def test_collect_findings_flags_expiring_certificate():
    soon = (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    run = AgentRun(
        "https://example.com",
        [
            _step(
                0,
                "check_tls",
                data={"host": "example.com", "port": 443, "protocol": "TLSv1.3", "cipher": "x", "cert": {"notAfter": soon}},
            )
        ],
        "done",
        "DeterministicPlanner",
    )
    findings = collect_findings(run)
    assert any("expires in" in f.summary for f in findings)


def test_overall_severity_scales_with_findings():
    assert overall_severity([]) == "low"
    assert overall_severity([Finding("x", "high", "s")]) == "high"
    assert overall_severity([Finding("x", "critical", "s")]) == "critical"


def test_build_report_uses_offline_narrator_by_default():
    run = AgentRun("https://example.com", [], "done", "DeterministicPlanner")
    report = build_report(run, narrator=Narrator(api_key=None))
    assert report.llm_backed is False
    assert "offline heuristic narrative" in report.narrative
    assert report.severity == "low"
