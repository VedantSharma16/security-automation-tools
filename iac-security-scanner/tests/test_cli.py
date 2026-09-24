import json
from pathlib import Path

import pytest

from iac_scanner.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_insecure_plan_exits_with_findings(capsys):
    code = main([str(EXAMPLES / "insecure_plan.json"), "--no-color"])
    out = capsys.readouterr().out
    assert code == EXIT_FINDINGS
    assert "CRITICAL" in out
    assert "S3-001" in out


def test_secure_plan_exits_clean(capsys):
    code = main([str(EXAMPLES / "secure_plan.json"), "--no-color"])
    out = capsys.readouterr().out
    assert code == EXIT_CLEAN
    assert "Clean scan" in out


def test_fail_on_none_always_exits_clean():
    code = main([str(EXAMPLES / "insecure_plan.json"), "--fail-on", "none", "--no-color"])
    assert code == EXIT_CLEAN


def test_missing_file_is_a_handled_error(capsys):
    code = main([str(EXAMPLES / "does_not_exist.json")])
    err = capsys.readouterr().err
    assert code == EXIT_ERROR
    assert "error:" in err


def test_invalid_json_is_a_handled_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    code = main([str(bad)])
    err = capsys.readouterr().err
    assert code == EXIT_ERROR
    assert "error:" in err


def test_json_format_is_valid_and_parseable(capsys):
    code = main([str(EXAMPLES / "insecure_plan.json"), "--format", "json", "--fail-on", "none"])
    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["finding_count"] > 0
    assert code == EXIT_CLEAN


def test_output_flag_writes_to_file(tmp_path):
    out_path = tmp_path / "report.md"
    code = main(
        [str(EXAMPLES / "insecure_plan.json"), "--format", "markdown", "--output", str(out_path), "--fail-on", "none"]
    )
    assert code == EXIT_CLEAN
    content = out_path.read_text()
    assert "# IaC Security Scan Report" in content


def test_min_severity_filters_displayed_findings(capsys):
    main([str(EXAMPLES / "insecure_plan.json"), "--format", "json", "--min-severity", "critical", "--fail-on", "none"])
    out = capsys.readouterr().out
    report = json.loads(out)
    assert all(f["severity"] == "critical" for f in report["findings"])


def test_secure_plan_fails_only_at_low_threshold():
    # nothing should exist above "low" in the secure fixture either
    code = main([str(EXAMPLES / "secure_plan.json"), "--fail-on", "low", "--no-color"])
    assert code == EXIT_CLEAN
