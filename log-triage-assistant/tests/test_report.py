import json
from pathlib import Path

from logtriage.detectors import run_all_detectors
from logtriage.parser import parse_file
from logtriage.report import build_report, to_json, to_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def _report_for(fixture_name: str) -> dict:
    path = FIXTURES / fixture_name
    events = parse_file(path, default_year=2026)
    findings = run_all_detectors(events)
    return build_report(path, events, findings)


def test_build_report_shape_on_malicious_fixture():
    report = _report_for("sample_auth.log")
    assert report["event_count"] == 12
    assert report["time_range"]["start"] < report["time_range"]["end"]
    assert report["summary"]["total_findings"] == len(report["findings"])
    assert report["narrative"] is None  # populated by the CLI, not the report builder


def test_build_report_on_clean_fixture_has_no_findings():
    report = _report_for("sample_auth_clean.log")
    assert report["findings"] == []
    assert report["summary"]["risk_score"] == 0


def test_to_json_round_trips():
    report = _report_for("sample_auth.log")
    report["narrative"] = "test narrative"
    parsed = json.loads(to_json(report))
    assert parsed["summary"]["total_findings"] == report["summary"]["total_findings"]
    assert parsed["narrative"] == "test narrative"


def test_to_markdown_contains_key_sections():
    report = _report_for("sample_auth.log")
    report["narrative"] = "The narrative text."
    md = to_markdown(report)
    assert "# Incident Triage Report" in md
    assert "## Summary" in md
    assert "## Findings" in md
    assert "## Analyst Narrative" in md
    assert "The narrative text." in md


def test_to_markdown_reports_no_findings_on_clean_fixture():
    report = _report_for("sample_auth_clean.log")
    md = to_markdown(report)
    assert "No security-relevant patterns detected." in md
