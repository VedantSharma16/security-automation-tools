import json
from pathlib import Path

import pytest

from ir_agent.cli import main

SAMPLE_PATH = str(Path(__file__).resolve().parent.parent / "examples" / "sample_incident.txt")


def test_cli_human_output(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    exit_code = main(["--file", SAMPLE_PATH, "--offline"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Severity:" in out
    assert "Agent trace" in out
    assert "Recommended actions:" in out


def test_cli_json_output_is_valid_and_complete(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    main(["--file", SAMPLE_PATH, "--json", "--offline"])
    out = capsys.readouterr().out

    payload = json.loads(out)
    assert payload["severity"] in ("critical", "high", "medium", "low")
    assert "trace" in payload
    assert "evidence" in payload
    assert payload["llm_backed"] is False


def test_cli_requires_input(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    with pytest.raises(SystemExit):
        main([])


def test_cli_respects_max_steps(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    main(["--file", SAMPLE_PATH, "--json", "--offline", "--max-steps", "1"])
    payload = json.loads(capsys.readouterr().out)
    action_steps = [s for s in payload["trace"] if s["tool"] != "finish"]
    assert len(action_steps) == 1
