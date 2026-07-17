import json
import os

from log_triage_agent.cli import main

SAMPLE_LOG = os.path.join(os.path.dirname(__file__), "..", "sample_logs", "auth.log")


def test_cli_markdown_output_against_sample_log(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    exit_code = main([SAMPLE_LOG, "--no-llm", "--year", "2024"])
    out = capsys.readouterr().out

    assert exit_code == 3  # critical finding present (compromised deploy credentials)
    assert "# Log Triage Report" in out
    assert "T1110" in out
    assert "T1078" in out


def test_cli_json_output_is_valid_and_contains_findings(capsys):
    exit_code = main([SAMPLE_LOG, "--no-llm", "--format", "json", "--year", "2024"])
    out = capsys.readouterr().out

    payload = json.loads(out)
    assert payload["events_analyzed"] > 0
    assert payload["narrative_source"] == "deterministic"
    assert any(f["mitre_attack"]["id"] == "T1110" for f in payload["findings"])
    assert exit_code == 3


def test_cli_returns_1_when_no_lines_recognized(tmp_path, capsys):
    empty_log = tmp_path / "empty.log"
    empty_log.write_text("nothing useful here\n")

    exit_code = main([str(empty_log), "--no-llm"])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "No recognizable" in err
