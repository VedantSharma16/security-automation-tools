import json

from secretscan.report import build_report, filter_by_min_severity, render_console, write_json
from secretscan.scanner import Finding
from secretscan.triage import TriageResult


def _finding(severity, rule_id="rule-1", fingerprint="fp1"):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category="cloud",
        description="a description",
        detector="rule",
        file_path="app.py",
        line_number=5,
        preview="AKIA****MNOP",
        fingerprint=fingerprint,
    )


def test_build_report_empty_findings():
    report = build_report([], scanned_at=0.0)
    assert report["finding_count"] == 0
    assert report["highest_severity"] is None


def test_build_report_sorts_by_severity_descending():
    findings = [_finding("low", "r1", "fp1"), _finding("critical", "r2", "fp2"), _finding("medium", "r3", "fp3")]
    report = build_report(findings, scanned_at=0.0)
    severities = [f["severity"] for f in report["findings"]]
    assert severities == ["critical", "medium", "low"]
    assert report["highest_severity"] == "critical"
    assert report["by_severity"]["critical"] == 1


def test_build_report_attaches_triage_when_provided():
    finding = _finding("high")
    triage = {finding.fingerprint: TriageResult(verdict="likely_secret", rationale="matched format", source="offline")}
    report = build_report([finding], triage=triage, scanned_at=0.0)
    assert report["findings"][0]["triage"]["verdict"] == "likely_secret"


def test_filter_by_min_severity():
    findings = [_finding("low", "r1", "fp1"), _finding("critical", "r2", "fp2")]
    report = build_report(findings, scanned_at=0.0)
    filtered = filter_by_min_severity(report, "high")
    assert filtered["finding_count"] == 1
    assert filtered["findings"][0]["severity"] == "critical"


def test_render_console_no_findings():
    report = build_report([], scanned_at=0.0)
    output = render_console(report, use_color=False)
    assert "No secrets detected" in output


def test_render_console_includes_finding_details():
    report = build_report([_finding("critical")], scanned_at=0.0)
    output = render_console(report, use_color=False)
    assert "rule-1" in output
    assert "app.py:5" in output
    assert "AKIA****MNOP" in output
    assert "\033[" not in output


def test_write_json_round_trips(tmp_path):
    report = build_report([_finding("high")], scanned_at=0.0)
    path = tmp_path / "report.json"
    write_json(report, path)

    loaded = json.loads(path.read_text())
    assert loaded["finding_count"] == 1
