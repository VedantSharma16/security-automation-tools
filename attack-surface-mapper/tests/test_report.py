from __future__ import annotations

import json

from asmapper.fetcher import FetchResult
from asmapper.models import Finding, Severity
from asmapper.planner import PlanStep, ScanState
from asmapper.report import build_report, render_console, render_markdown, write_json, write_markdown


def _sample_state() -> ScanState:
    target = FetchResult(url="https://example.com", status=200, headers={}, body="")
    state = ScanState(base_url="https://example.com", target=target, planner_mode="offline")
    state.findings = [
        Finding(id="a", title="Missing HSTS", severity=Severity.MEDIUM, detail="d1", category="headers", recommendation="add HSTS"),
        Finding(id="b", title="Detected nginx", severity=Severity.INFO, detail="d2", category="fingerprint"),
    ]
    state.trace = [PlanStep(tool="run_header_audit", reason="fixed order")]
    state.agent_assessment = "Offline summary."
    return state


def test_build_report_sorts_findings_most_severe_first():
    report = build_report(_sample_state())
    assert [f["severity"] for f in report["findings"]] == ["MEDIUM", "INFO"]
    assert report["summary"]["total_findings"] == 2
    assert report["target"] == "https://example.com"


def test_render_console_filters_by_min_severity():
    report = build_report(_sample_state())
    out_all = render_console(report, min_severity="info", use_color=False)
    out_medium = render_console(report, min_severity="medium", use_color=False)
    assert "Detected nginx" in out_all
    assert "Detected nginx" not in out_medium
    assert "Missing HSTS" in out_medium


def test_render_console_includes_assessment_and_trace():
    report = build_report(_sample_state())
    out = render_console(report, use_color=False)
    assert "Offline summary." in out
    assert "run_header_audit" in out


def test_render_console_no_color_has_no_ansi_codes():
    report = build_report(_sample_state())
    out = render_console(report, use_color=False)
    assert "\033[" not in out


def test_render_markdown_includes_findings_and_trace():
    report = build_report(_sample_state())
    md = render_markdown(report)
    assert "# Attack Surface Report — https://example.com" in md
    assert "Missing HSTS" in md
    assert "`run_header_audit`" in md


def test_write_json_and_markdown_roundtrip(tmp_path):
    report = build_report(_sample_state())
    json_path = tmp_path / "report.json"
    md_path = tmp_path / "report.md"

    write_json(report, json_path)
    write_markdown(report, md_path)

    loaded = json.loads(json_path.read_text())
    assert loaded["target"] == "https://example.com"
    assert "Missing HSTS" in md_path.read_text()


def test_render_console_clean_scan_has_no_findings_message():
    target = FetchResult(url="https://example.com", status=200, headers={}, body="")
    state = ScanState(base_url="https://example.com", target=target, planner_mode="offline")
    report = build_report(state)
    out = render_console(report, use_color=False)
    assert "No findings at or above the selected severity." in out
