import datetime as dt
import json

from recon.findings import Finding
from recon.report import build_report, filter_by_min_severity, render_console, render_markdown, write_json


def sample_findings():
    return [
        Finding(category="ports", title="Redis exposed", severity="critical", description="d", recommendation="r"),
        Finding(category="dns", title="Subdomains found", severity="info", description="d"),
    ]


def test_build_report_sorts_by_severity_descending():
    report = build_report("example.com", sample_findings(), scanned_at=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
    assert report["findings"][0]["severity"] == "critical"
    assert report["findings"][1]["severity"] == "info"
    assert report["finding_count"] == 2
    assert report["risk"]["label"] == "critical"


def test_filter_by_min_severity():
    report = build_report("example.com", sample_findings())
    filtered = filter_by_min_severity(report, "high")
    assert filtered["finding_count"] == 1
    assert filtered["findings"][0]["severity"] == "critical"


def test_render_console_no_findings():
    report = build_report("example.com", [])
    output = render_console(report, use_color=False)
    assert "No findings" in output


def test_render_console_includes_findings():
    report = build_report("example.com", sample_findings())
    output = render_console(report, use_color=False)
    assert "Redis exposed" in output
    assert "CRITICAL" in output


def test_render_markdown_has_table():
    report = build_report("example.com", sample_findings())
    md = render_markdown(report)
    assert "| Severity | Category |" in md
    assert "Redis exposed" in md


def test_write_json(tmp_path):
    report = build_report("example.com", sample_findings())
    path = tmp_path / "report.json"
    write_json(report, path)
    loaded = json.loads(path.read_text())
    assert loaded["target"] == "example.com"
    assert loaded["finding_count"] == 2
