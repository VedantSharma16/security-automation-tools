import json
from pathlib import Path

from sigmalite.cli import main

ROOT = Path(__file__).resolve().parent.parent
R, E = str(ROOT / "rules"), str(ROOT / "samples" / "events.jsonl")


def test_validate(capsys):
    assert main(["validate", R]) == 0
    assert "valid" in capsys.readouterr().out


def test_run_json_and_fail_on_match(capsys):
    assert main(["run", R, E, "--json", "--fail-on-match"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert any(d["rule_id"] == "win-lsass-dump" for d in data)


def test_run_no_matches_exit_zero(tmp_path, capsys):
    ev = tmp_path / "e.jsonl"
    ev.write_text('{"Image": "notepad.exe"}\n')
    assert main(["run", R, str(ev), "--fail-on-match"]) == 0


def test_bad_path_returns_2(capsys):
    assert main(["validate", "/nonexistent"]) == 2


def test_coverage_cli(capsys):
    assert main(["coverage", R, "--target", "T1059,T9999"]) == 0
    assert "T9999" in capsys.readouterr().out
