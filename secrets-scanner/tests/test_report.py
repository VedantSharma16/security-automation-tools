from secretscan.finding import Finding
from secretscan.report import build_report, build_sarif, filter_by_min_severity, render_console


def _finding(severity="high", rule_id="r1"):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category="cloud-credential",
        description="a test finding",
        file_path="config.py",
        redacted="AKIA...MPLE",
        fingerprint="fp1",
        source="working-tree",
        line=3,
        context_key="AWS_KEY",
    )


def test_build_report_counts_and_sorts_by_severity():
    findings = [_finding("low"), _finding("critical"), _finding("medium")]
    report = build_report(findings, ["/tmp/repo"])

    assert report["finding_count"] == 3
    assert report["highest_severity"] == "critical"
    assert [f["severity"] for f in report["findings"]] == ["critical", "medium", "low"]
    assert report["by_severity"]["critical"] == 1


def test_build_report_with_no_findings():
    report = build_report([], ["/tmp/repo"])
    assert report["finding_count"] == 0
    assert report["highest_severity"] is None


def test_filter_by_min_severity_drops_lower_severities():
    findings = [_finding("low"), _finding("critical")]
    report = build_report(findings, ["/tmp/repo"])
    filtered = filter_by_min_severity(report, "high")
    assert filtered["finding_count"] == 1
    assert filtered["findings"][0]["severity"] == "critical"


def test_render_console_includes_redacted_value_not_raw():
    report = build_report([_finding()], ["/tmp/repo"])
    text = render_console(report, use_color=False)
    assert "AKIA...MPLE" in text
    assert "r1" in text


def test_render_console_no_findings_message():
    report = build_report([], ["/tmp/repo"])
    text = render_console(report, use_color=False)
    assert "No secrets found" in text


def test_build_sarif_has_matching_rule_and_result_counts():
    findings = [_finding("high", "rule-a"), _finding("critical", "rule-b")]
    report = build_report(findings, ["/tmp/repo"])
    sarif = build_sarif(report)

    run = sarif["runs"][0]
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"rule-a", "rule-b"}
    assert len(run["results"]) == 2
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "config.py"
