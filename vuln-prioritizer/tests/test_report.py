from pathlib import Path

from vuln_prioritizer.pipeline import prioritize
from vuln_prioritizer.report import build_report, to_json, to_markdown

FIXTURES = Path(__file__).resolve().parent.parent / "examples"


def _report():
    scored = prioritize(FIXTURES / "sample_scan.csv", FIXTURES / "sample_assets.json")
    return build_report(FIXTURES / "sample_scan.csv", FIXTURES / "sample_assets.json", scored)


def test_build_report_shape():
    report = _report()
    assert report["summary"]["total_findings"] == 8
    assert len(report["findings"]) == 8
    assert report["narrative"] is None


def test_to_json_round_trips():
    import json

    report = _report()
    parsed = json.loads(to_json(report))
    assert parsed["summary"]["total_findings"] == 8


def test_to_markdown_contains_key_sections():
    report = _report()
    md = to_markdown(report)
    assert "# Vulnerability Remediation Priority Report" in md
    assert "## Summary" in md
    assert "## Prioritized Findings" in md
    assert "CVE-2021-44228" in md


def test_to_markdown_respects_top_n():
    report = _report()
    md = to_markdown(report, top_n=1)
    assert md.count("### [") == 1


def test_to_markdown_includes_narrative_when_present():
    report = _report()
    report["narrative"] = "Test narrative content."
    md = to_markdown(report)
    assert "## Executive Narrative" in md
    assert "Test narrative content." in md


def test_to_markdown_handles_no_findings():
    report = _report()
    report["findings"] = []
    md = to_markdown(report)
    assert "No findings to report." in md
