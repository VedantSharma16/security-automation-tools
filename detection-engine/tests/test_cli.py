import json
from pathlib import Path

from sigmalite.cli import main

ROOT = Path(__file__).parent.parent
RULES, EVENTS = str(ROOT / "rules"), str(ROOT / "samples/events.jsonl")


def test_scan_json_and_fail_on_alert(capsys):
    assert main(["scan", "--rules", RULES, "--events", EVENTS, "--format", "json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) >= 7
    assert main(["scan", "--rules", RULES, "--events", EVENTS, "--fail-on-alert"]) == 2


def test_test_validate_coverage(capsys):
    assert main(["test", "--rules", RULES]) == 0
    assert main(["validate", "--rules", RULES]) == 0
    assert main(["coverage", "--rules", RULES, "--format", "json"]) == 0
    out = capsys.readouterr().out
    assert "T1059.001" in out and "lateral_movement" in out


def test_errors_exit_one(capsys, tmp_path):
    assert main(["validate", "--rules", str(tmp_path / "nope.json")]) == 1
    assert "error:" in capsys.readouterr().err
