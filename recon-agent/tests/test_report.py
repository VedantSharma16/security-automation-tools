import json

from recon_agent.agent import Action, AgentState
from recon_agent.models import AgentStep, Finding
from recon_agent.report import build_report, highest_severity, render_console, render_markdown, write_json


def _finding(id_="f1", severity="high"):
    return Finding(
        id=id_,
        title="Test finding",
        severity=severity,
        category="test",
        evidence="evidence",
        recommendation="fix it",
        source_url="https://example.com",
    )


def test_highest_severity_empty():
    assert highest_severity([]) is None


def test_highest_severity_picks_max_rank():
    findings = [_finding("f1", "low"), _finding("f2", "critical"), _finding("f3", "medium")]
    assert highest_severity(findings) == "critical"


def test_build_report_sorts_findings_by_severity_desc():
    state = AgentState(host="example.com")
    state.done = True
    state.findings = [_finding("f-low", "low"), _finding("f-crit", "critical")]
    state.steps = [AgentStep(tool="probe_https", args={"host": "example.com"}, result=None, note="start")]

    report = build_report(state)

    assert report["host"] == "example.com"
    assert report["finding_count"] == 2
    assert report["highest_severity"] == "critical"
    assert [f["id"] for f in report["findings"]] == ["f-crit", "f-low"]


def test_render_console_clean_scan():
    state = AgentState(host="example.com")
    report = build_report(state)
    text = render_console(report, use_color=False)
    assert "No header/TLS findings" in text


def test_render_console_lists_findings():
    state = AgentState(host="example.com")
    state.findings = [_finding()]
    report = build_report(state)
    text = render_console(report, use_color=False)
    assert "Test finding" in text
    assert "evidence" in text


def test_render_markdown_includes_findings_and_steps():
    state = AgentState(host="example.com")
    state.findings = [_finding()]
    state.steps = [AgentStep(tool="probe_https", args={"host": "example.com"}, result=None, note="start")]
    report = build_report(state)

    md = render_markdown(report)
    assert "# Recon report — example.com" in md
    assert "Test finding" in md
    assert "probe_https" in md


def test_write_json_round_trips(tmp_path):
    state = AgentState(host="example.com")
    state.findings = [_finding()]
    report = build_report(state)

    out = tmp_path / "report.json"
    write_json(report, out)

    loaded = json.loads(out.read_text())
    assert loaded["host"] == "example.com"
    assert loaded["finding_count"] == 1
