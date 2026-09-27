from secret_scanner.findings import Finding
from secret_scanner.report import (
    build_report,
    filter_by_min_severity,
    render_console,
    render_markdown,
    write_json,
    write_markdown,
)


def _finding(**overrides):
    defaults = dict(
        rule_id="aws-access-key-id",
        category="signature",
        severity="critical",
        file_path="config.py",
        line_number=1,
        redacted_value="AKIA****MNOP",
        description="AWS access key ID",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_build_report_empty():
    report = build_report([], [])
    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["highest_severity"] is None
    assert report["summary"]["risk_score"] == 0


def test_build_report_combines_working_tree_and_history():
    wt = [_finding(severity="high")]
    history = [_finding(severity="critical", source="git_history", commit_hash="abc123",
                         commit_author="Jane", commit_date="2026-01-01", commit_subject="oops")]
    report = build_report(wt, history)
    assert report["summary"]["total_findings"] == 2
    assert report["summary"]["working_tree_findings"] == 1
    assert report["summary"]["git_history_findings"] == 1
    assert report["summary"]["highest_severity"] == "critical"


def test_filter_by_min_severity_drops_lower_severities():
    findings = [_finding(severity="low"), _finding(severity="high", line_number=2)]
    report = build_report(findings)
    filtered = filter_by_min_severity(report, "high")
    assert filtered["summary"]["total_findings"] == 1
    assert filtered["findings"][0]["severity"] == "high"


def test_filter_by_min_severity_empty_result_has_no_highest_severity():
    report = build_report([_finding(severity="low")])
    filtered = filter_by_min_severity(report, "critical")
    assert filtered["summary"]["total_findings"] == 0
    assert filtered["summary"]["highest_severity"] is None


def test_render_console_clean():
    report = build_report([])
    assert render_console(report) == "No secrets detected."


def test_render_console_lists_findings_without_leaking_secret():
    secret_fragment = "AKIA****MNOP"
    report = build_report([_finding(redacted_value=secret_fragment)])
    text = render_console(report, use_color=False)
    assert "config.py:1" in text
    assert secret_fragment in text
    assert "AKIA****" in text  # confirms it's the redacted form, not a raw secret


def test_render_console_includes_commit_info_for_history_findings():
    finding = _finding(source="git_history", commit_hash="abc123", commit_author="Jane",
                        commit_date="2026-01-01", commit_subject="oops")
    report = build_report([], [finding])
    text = render_console(report, use_color=False)
    assert "abc123" in text
    assert "Jane" in text


def test_render_markdown_table():
    report = build_report([_finding()])
    md = render_markdown(report)
    assert md.startswith("# Secret Scan Report")
    assert "| Severity | Rule | Location | Value |" in md
    assert "aws-access-key-id" in md


def test_write_json_and_markdown_roundtrip(tmp_path):
    import json

    report = build_report([_finding()])
    json_path = tmp_path / "report.json"
    md_path = tmp_path / "report.md"

    write_json(report, json_path)
    write_markdown(report, md_path)

    assert json.loads(json_path.read_text())["summary"]["total_findings"] == 1
    assert "Secret Scan Report" in md_path.read_text()
