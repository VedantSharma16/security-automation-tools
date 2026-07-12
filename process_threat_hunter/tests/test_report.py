import json

from hunter.report import (
    build_report,
    filter_by_min_severity,
    highest_severity,
    render_console,
    write_json,
)
from hunter.rules import load_rules
from hunter.scanner import ProcessInfo, evaluate


def make_process(pid, name):
    return ProcessInfo(pid=pid, name=name, exe=name, cmdline=[name], username="alice", create_time=0.0)


def make_rules(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        "- id: low-rule\n"
        "  pattern: 'wireshark'\n"
        "  match_fields: [name]\n"
        "  severity: low\n"
        "  mitre_tactic: Collection\n"
        "  mitre_technique: T1040\n"
        "- id: critical-rule\n"
        "  pattern: 'mimikatz'\n"
        "  match_fields: [name]\n"
        "  severity: critical\n"
        "  mitre_tactic: Credential Access\n"
        "  mitre_technique: T1003\n"
    )
    return load_rules(path)


def test_highest_severity_picks_max():
    assert highest_severity([]) is None


def test_build_report_orders_findings_by_severity_desc(tmp_path):
    rules = make_rules(tmp_path)
    processes = [make_process(1, "wireshark"), make_process(2, "mimikatz")]
    findings = evaluate(processes, rules)

    report = build_report(processes, findings, [], scanned_at=0.0)

    assert report["finding_count"] == 2
    assert report["highest_severity"] == "critical"
    assert [f["severity"] for f in report["findings"]] == ["critical", "low"]


def test_filter_by_min_severity_drops_lower(tmp_path):
    rules = make_rules(tmp_path)
    processes = [make_process(1, "wireshark"), make_process(2, "mimikatz")]
    findings = evaluate(processes, rules)
    report = build_report(processes, findings, [], scanned_at=0.0)

    filtered = filter_by_min_severity(report, "critical")

    assert filtered["finding_count"] == 1
    assert filtered["findings"][0]["rule_id"] == "critical-rule"


def test_render_console_reports_clean_scan():
    report = build_report([], [], [], scanned_at=0.0)
    output = render_console(report, use_color=False)
    assert "No rule matches" in output


def test_render_console_includes_new_processes(tmp_path):
    report = build_report([], [], [make_process(5, "unknown_binary")], scanned_at=0.0)
    output = render_console(report, use_color=False)
    assert "New processes since baseline: 1" in output
    assert "unknown_binary" in output


def test_write_json_produces_valid_json(tmp_path):
    report = build_report([], [], [], scanned_at=0.0)
    out_path = tmp_path / "report.json"

    write_json(report, out_path)

    reloaded = json.loads(out_path.read_text())
    assert reloaded["finding_count"] == 0
