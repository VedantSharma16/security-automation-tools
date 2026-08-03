from secretscan.report import build_report, filter_by_min_severity, render_console, risk_score
from secretscan.scanner import Finding


def _finding(severity, rule_id="test-rule", **overrides):
    defaults = dict(
        file="app.py",
        line_number=1,
        rule_id=rule_id,
        severity=severity,
        description="a finding",
        redacted_secret="ab**cd",
        line_preview="secret = 'ab12cd'",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestRiskScore:
    def test_no_findings_is_zero(self):
        assert risk_score([]) == 0

    def test_score_is_capped_at_100(self):
        findings = [_finding("critical") for _ in range(10)]
        assert risk_score(findings) == 100

    def test_critical_outweighs_many_lows(self):
        assert risk_score([_finding("critical")]) > risk_score([_finding("low") for _ in range(5)])


class TestBuildReport:
    def test_counts_by_severity(self):
        findings = [_finding("critical"), _finding("low"), _finding("low")]
        report = build_report(findings, scan_targets={"working_tree": "."})
        assert report["findings_by_severity"] == {"low": 2, "medium": 0, "high": 0, "critical": 1}
        assert report["finding_count"] == 3
        assert report["highest_severity"] == "critical"

    def test_findings_sorted_highest_severity_first(self):
        findings = [_finding("low"), _finding("critical"), _finding("medium")]
        report = build_report(findings, scan_targets={"working_tree": "."})
        assert [f["severity"] for f in report["findings"]] == ["critical", "medium", "low"]

    def test_empty_findings(self):
        report = build_report([], scan_targets={"working_tree": "."})
        assert report["finding_count"] == 0
        assert report["highest_severity"] is None
        assert report["risk_score"] == 0


class TestFilterByMinSeverity:
    def test_filters_out_below_threshold(self):
        findings = [_finding("critical"), _finding("low")]
        report = build_report(findings, scan_targets={"working_tree": "."})
        filtered = filter_by_min_severity(report, "high")
        assert filtered["finding_count"] == 1
        assert filtered["findings"][0]["severity"] == "critical"


class TestRenderConsole:
    def test_clean_report_shows_checkmark(self):
        report = build_report([], scan_targets={"working_tree": "."})
        rendered = render_console(report, use_color=False)
        assert "No secrets detected" in rendered

    def test_findings_are_listed_with_location(self):
        findings = [_finding("critical", rule_id="aws-access-key-id")]
        report = build_report(findings, scan_targets={"working_tree": "."})
        rendered = render_console(report, use_color=False)
        assert "aws-access-key-id" in rendered
        assert "app.py:1" in rendered

    def test_no_color_strips_ansi_codes(self):
        findings = [_finding("critical")]
        report = build_report(findings, scan_targets={"working_tree": "."})
        rendered = render_console(report, use_color=False)
        assert "\033[" not in rendered

    def test_git_history_commit_shown_in_location(self):
        findings = [_finding("high", source="git-history", commit="abc123def")]
        report = build_report(findings, scan_targets={"working_tree": ".", "git_history": True, "all_branches": True})
        rendered = render_console(report, use_color=False)
        assert "commit abc123def" in rendered
