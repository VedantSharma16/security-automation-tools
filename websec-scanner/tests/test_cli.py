from __future__ import annotations

import json

from websec.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main


def test_refuses_to_scan_without_authorized_flag(live_target, capsys):
    code = main([live_target])
    assert code == EXIT_ERROR
    assert "--authorized" in capsys.readouterr().err


def test_scan_reports_findings_and_exits_nonzero(live_target, capsys):
    code = main([live_target, "--authorized", "--no-color"])
    out = capsys.readouterr().out
    assert code == EXIT_FINDINGS
    assert "Findings:" in out


def test_min_severity_filters_output(live_target, capsys):
    code = main([live_target, "--authorized", "--no-color", "--min-severity", "critical"])
    out = capsys.readouterr().out
    # The exposed .git/config is the only critical-severity finding on the target.
    assert "critical" in out.lower()
    assert code in (EXIT_CLEAN, EXIT_FINDINGS)


def test_json_out_writes_valid_report(live_target, tmp_path):
    out_path = tmp_path / "report.json"
    main([live_target, "--authorized", "--json-out", str(out_path)])
    data = json.loads(out_path.read_text())
    assert data["target"] == live_target
    assert "findings" in data


def test_md_out_writes_report(live_target, tmp_path):
    out_path = tmp_path / "report.md"
    main([live_target, "--authorized", "--md-out", str(out_path)])
    content = out_path.read_text()
    assert content.startswith("# Web Security Scan Report")


def test_invalid_target_scheme_returns_error(capsys):
    code = main(["ftp://example.test", "--authorized"])
    assert code == EXIT_ERROR
    assert "Error" in capsys.readouterr().err
