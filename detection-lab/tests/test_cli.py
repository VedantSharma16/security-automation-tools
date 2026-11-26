import json
from pathlib import Path

import pytest

from detlab.cli import main

ROOT = Path(__file__).resolve().parent.parent
RULES = str(ROOT / "rules")


def test_scan_text_output_and_exit_code(capsys):
    code = main(["scan", "--rules", RULES, "--events", str(ROOT / "samples" / "incident_timeline.jsonl")])
    out = capsys.readouterr().out
    assert code == 1  # alerts found -> non-zero, so it can gate a pipeline
    assert "LSASS Memory Dump via Comsvcs MiniDump" in out and "critical=" in out


def test_scan_json_and_output_file(tmp_path, capsys):
    events = tmp_path / "e.jsonl"
    events.write_text('{"Image": "notepad.exe"}\n')
    out_file = tmp_path / "r.json"
    code = main(["scan", "--rules", RULES, "--events", str(events), "--json", "--output", str(out_file)])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["alert_count"] == 0
    assert json.loads(out_file.read_text())["events_scanned"] == 1


def test_lint_clean_and_dirty(tmp_path, capsys):
    assert main(["lint", RULES]) == 0
    bad = tmp_path / "bad.yml"
    bad.write_text("title: x\ndetection: {sel: {F|nope: 1}, condition: sel}\n")
    assert main(["lint", str(bad)]) == 1
    assert "unsupported modifier" in capsys.readouterr().out


def test_lint_strict_fails_on_warnings(tmp_path):
    rule = tmp_path / "warn.yml"
    rule.write_text(
        "title: x\nid: 11111111-2222-3333-4444-555555555555\nlevel: low\nlogsource: {product: windows}\n"
        "detection: {sel: {F: 1}, condition: sel}\n"
    )
    assert main(["lint", str(rule)]) == 0
    assert main(["lint", "--strict", str(rule)]) == 1


def test_test_command(capsys):
    assert main(["test", "--rules", RULES, "--tests", str(ROOT / "rule_tests"), "--require-all"]) == 0
    assert "9/9 rule tests passed" in capsys.readouterr().out


def test_test_command_detects_regression(tmp_path, capsys):
    case = tmp_path / "t.yml"
    case.write_text(
        "rule_id: e5221b69-14e9-4024-8724-74f34f1a2a1a\n"
        "true_positives:\n  - {Image: 'C:\\certutil.exe', CommandLine: 'certutil -decode a b'}\n"
    )
    assert main(["test", "--rules", RULES, "--tests", str(case)]) == 1
    assert "did NOT match true_positives[0]" in capsys.readouterr().out


def test_coverage_json(capsys):
    assert main(["coverage", "--rules", RULES, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "T1003.001" in data["covered_techniques"] and "defense_evasion" in data["gaps"]


def test_draft_offline_writes_rule(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = tmp_path / "rule.yml"
    samples = ROOT / "samples" / "authoring"
    code = main([
        "draft", "--offline",
        "--description", str(samples / "log_clearing_description.txt"),
        "--positives", str(samples / "log_clearing_positives.jsonl"),
        "--negatives", str(samples / "log_clearing_negatives.jsonl"),
        "--tags", "attack.defense_evasion,attack.t1070.001",
        "--out", str(out),
    ])
    assert code == 0
    assert "wevtutil.exe" in out.read_text()


def test_missing_file_returns_error_code(capsys):
    assert main(["scan", "--rules", "/nope", "--events", "/nope.jsonl"]) == 2
    assert "error:" in capsys.readouterr().err


def test_requires_subcommand():
    with pytest.raises(SystemExit):
        main([])
