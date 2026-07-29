import json

from secret_sentinel.report import build_report, filter_by_min_severity, render_console, write_json
from secret_sentinel.scanner import Finding


def _finding(severity: str, signature_id: str = "generic-high-entropy-string", **overrides) -> Finding:
    defaults = dict(
        file="app.py",
        line_number=10,
        signature_id=signature_id,
        category="generic-secret",
        severity=severity,
        confidence="low",
        description="test finding",
        redacted_value="Xk29****4Rb",
        entropy=4.0,
        fingerprint=f"fp-{severity}",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_build_report_empty_findings():
    report = build_report([], scan_type="filesystem", targets=["."])
    assert report["finding_count"] == 0
    assert report["summary"]["risk_score"] == 0
    assert report["summary"]["highest_severity"] is None


def test_build_report_computes_risk_score_and_highest_severity():
    findings = [_finding("low"), _finding("critical"), _finding("medium")]
    report = build_report(findings, scan_type="filesystem", targets=["."])
    assert report["finding_count"] == 3
    assert report["summary"]["highest_severity"] == "critical"
    assert report["summary"]["risk_score"] == 5 + 50 + 15


def test_build_report_caps_risk_score_at_100():
    findings = [_finding("critical", fingerprint=f"fp-{i}") for i in range(5)]
    report = build_report(findings, scan_type="filesystem", targets=["."])
    assert report["summary"]["risk_score"] == 100


def test_build_report_sorts_findings_by_severity_descending():
    findings = [_finding("low"), _finding("critical"), _finding("medium")]
    report = build_report(findings, scan_type="filesystem", targets=["."])
    severities = [f["severity"] for f in report["findings"]]
    assert severities == ["critical", "medium", "low"]


def test_filter_by_min_severity_drops_below_threshold():
    findings = [_finding("low"), _finding("high")]
    report = build_report(findings, scan_type="filesystem", targets=["."])
    filtered = filter_by_min_severity(report, "high")
    assert filtered["finding_count"] == 1
    assert filtered["findings"][0]["severity"] == "high"


def test_render_console_reports_clean_scan():
    report = build_report([], scan_type="filesystem", targets=["."])
    output = render_console(report, use_color=False)
    assert "No secrets detected" in output


def test_render_console_includes_finding_details():
    report = build_report([_finding("high", signature_id="github-token")], scan_type="filesystem", targets=["repo/"])
    output = render_console(report, use_color=False)
    assert "github-token" in output
    assert "app.py:10" in output
    assert "Xk29****4Rb" in output
    assert "\033[" not in output  # no ANSI codes when use_color=False


def test_render_console_includes_llm_triage_when_present():
    report = build_report([_finding("medium")], scan_type="filesystem", targets=["."])
    report["findings"][0]["llm_triage"] = {"verdict": "true_positive", "rationale": "looks real"}
    output = render_console(report, use_color=False)
    assert "true_positive" in output
    assert "looks real" in output


def test_render_console_includes_commit_when_present():
    report = build_report(
        [_finding("high", signature_id="github-token", commit="abc1234")],
        scan_type="git-history",
        targets=["."],
    )
    output = render_console(report, use_color=False)
    assert "commit abc1234" in output


def test_write_json_round_trips(tmp_path):
    report = build_report([_finding("critical")], scan_type="filesystem", targets=["."])
    path = tmp_path / "report.json"
    write_json(report, path)
    loaded = json.loads(path.read_text())
    assert loaded["finding_count"] == 1
    assert loaded["findings"][0]["severity"] == "critical"
