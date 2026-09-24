import json

from iac_scanner.models import Finding
from iac_scanner.report import (
    build_report,
    filter_by_min_severity,
    highest_severity,
    render_markdown,
    render_text,
    write_json,
)
from tests.helpers import make_resource


def _finding(severity, rule_id="R-1"):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        resource_address="aws_s3_bucket.x",
        resource_type="aws_s3_bucket",
        title="Example finding",
        description="Something bad.",
        remediation="Fix it.",
        references=("https://example.com",),
    )


def test_highest_severity_picks_max_rank():
    assert highest_severity([_finding("low"), _finding("critical"), _finding("medium")]) == "critical"


def test_highest_severity_none_when_empty():
    assert highest_severity([]) is None


def test_build_report_counts_and_shape():
    resources = [make_resource("aws_s3_bucket", {})]
    findings = [_finding("high"), _finding("high", "R-2"), _finding("low", "R-3")]
    report = build_report(resources, findings)
    assert report["resource_count"] == 1
    assert report["finding_count"] == 3
    assert report["highest_severity"] == "high"
    assert report["severity_counts"]["high"] == 2
    assert report["severity_counts"]["low"] == 1
    assert report["severity_counts"]["critical"] == 0
    assert len(report["findings"]) == 3
    assert report["findings"][0]["rule_id"] == "R-1"


def test_filter_by_min_severity_drops_low_severity_findings():
    report = build_report([], [_finding("low"), _finding("critical", "R-2")])
    filtered = filter_by_min_severity(report, "high")
    assert filtered["finding_count"] == 1
    assert filtered["findings"][0]["severity"] == "critical"
    # original report is untouched
    assert report["finding_count"] == 2


def test_render_text_includes_findings_and_clean_message():
    report = build_report([], [_finding("critical")])
    text = render_text(report, use_color=False)
    assert "CRITICAL" in text
    assert "R-1" in text
    assert "Fix it." in text

    clean_report = build_report([], [])
    clean_text = render_text(clean_report, use_color=False)
    assert "Clean scan" in clean_text


def test_render_markdown_has_table_and_details():
    report = build_report([], [_finding("high")])
    markdown = render_markdown(report)
    assert "| Severity | Rule | Resource | Title |" in markdown
    assert "HIGH" in markdown
    assert "### R-1" in markdown


def test_write_json_round_trips(tmp_path):
    report = build_report([], [_finding("medium")])
    path = tmp_path / "report.json"
    write_json(report, path)
    loaded = json.loads(path.read_text())
    assert loaded["finding_count"] == 1
    assert loaded["findings"][0]["rule_id"] == "R-1"
