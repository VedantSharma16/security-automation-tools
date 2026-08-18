import json

import pytest

from codesec.findings import Finding, ScanResult, Severity
from codesec.report import render, to_json, to_text


def _finding(rule_id="rule", severity=Severity.HIGH, file="a.py", line=1):
    return Finding(
        rule_id=rule_id,
        title="Test Finding",
        severity=severity,
        cwe="CWE-000",
        file=file,
        line=line,
        snippet="x = 1",
        description="desc",
        remediation="fix it",
    )


def test_to_text_no_findings_reports_clean():
    result = ScanResult(files_scanned=3)
    text = to_text(result)
    assert "No findings" in text
    assert "Files scanned: 3" in text


def test_to_text_lists_each_finding():
    result = ScanResult(files_scanned=1)
    result.add(_finding())
    text = to_text(result)
    assert "Test Finding" in text
    assert "CWE-000" in text
    assert "a.py:1" in text


def test_to_text_includes_narrative_when_given():
    result = ScanResult()
    text = to_text(result, narrative="Everything looks fine.")
    assert "ANALYST NARRATIVE" in text
    assert "Everything looks fine." in text


def test_to_json_round_trips_summary_and_findings():
    result = ScanResult(files_scanned=2)
    result.add(_finding(severity=Severity.CRITICAL))
    result.add(_finding(severity=Severity.LOW, line=5))

    payload = json.loads(to_json(result))
    assert payload["summary"]["files_scanned"] == 2
    assert payload["summary"]["total_findings"] == 2
    assert payload["summary"]["by_severity"]["CRITICAL"] == 1
    assert payload["summary"]["by_severity"]["LOW"] == 1
    assert len(payload["findings"]) == 2


def test_to_json_sorts_findings_by_severity_descending():
    result = ScanResult()
    result.add(_finding(rule_id="low-one", severity=Severity.LOW))
    result.add(_finding(rule_id="critical-one", severity=Severity.CRITICAL))

    payload = json.loads(to_json(result))
    assert payload["findings"][0]["rule_id"] == "critical-one"
    assert payload["findings"][-1]["rule_id"] == "low-one"


def test_render_dispatches_on_format():
    result = ScanResult()
    assert "No findings" in render(result, "text")
    assert json.loads(render(result, "json"))["summary"]["total_findings"] == 0


def test_render_rejects_unknown_format():
    with pytest.raises(ValueError):
        render(ScanResult(), "xml")


def test_max_severity_and_counts():
    result = ScanResult()
    assert result.max_severity() is None
    result.add(_finding(severity=Severity.MEDIUM))
    result.add(_finding(severity=Severity.HIGH))
    assert result.max_severity() == Severity.HIGH
    assert result.count_by_severity()["HIGH"] == 1
