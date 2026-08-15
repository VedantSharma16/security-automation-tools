import json

from secretscanner.gitscan import GitFinding
from secretscanner.report import build_report, to_json, to_markdown
from secretscanner.scanner import Finding
from secretscanner.triage import triage_finding


def _finding(**overrides):
    defaults = dict(
        file="app/settings.py",
        line_number=10,
        pattern_name="AWS Access Key ID",
        category="cloud",
        severity="critical",
        detector="regex",
        redacted_value="AKIA************ERTY",
        remediation="Rotate it.",
        line_preview="AWS_KEY = 'AKIAZQTKPMNBVCXWERTY'",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_build_report_combines_working_tree_and_history():
    working_tree = [triage_finding(_finding())]
    git_finding = GitFinding(commit="abc1234", author="Dev", date="2026-01-01", finding=_finding(file="old.py"))
    history = [(triage_finding(git_finding.finding, source="git-history"), git_finding)]

    report = build_report("/repo", working_tree, history, narrative="test narrative")

    assert report["summary"]["total_findings"] == 2
    assert report["summary"]["working_tree_findings"] == 1
    assert report["summary"]["git_history_findings"] == 1
    assert report["summary"]["by_severity"]["critical"] == 2
    assert report["narrative"] == "test narrative"
    assert len(report["findings"]) == 2
    history_entry = next(e for e in report["findings"] if e["source"] == "git-history")
    assert history_entry["commit"] == "abc1234"
    assert history_entry["author"] == "Dev"


def test_build_report_empty_is_valid():
    report = build_report("/repo", [], [], narrative="all clear")
    assert report["summary"]["total_findings"] == 0
    assert report["findings"] == []


def test_to_json_round_trips():
    report = build_report("/repo", [triage_finding(_finding())], [], narrative="n")
    parsed = json.loads(to_json(report))
    assert parsed["summary"]["total_findings"] == 1


def test_to_markdown_contains_key_sections():
    report = build_report("/repo", [triage_finding(_finding())], [], narrative="Rotate everything.")
    md = to_markdown(report)
    assert "# Secret Scan Report" in md
    assert "## Summary" in md
    assert "## Analyst Narrative" in md
    assert "Rotate everything." in md
    assert "AWS Access Key ID" in md


def test_to_markdown_handles_no_findings():
    report = build_report("/repo", [], [], narrative="Clean scan.")
    md = to_markdown(report)
    assert "No findings." in md
