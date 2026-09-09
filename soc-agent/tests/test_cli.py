import json
from pathlib import Path

import pytest

from soc_agent.cli import main

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def test_cli_investigate_critical_alert_exits_1_by_default(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    exit_code = main(
        [
            "investigate",
            "--alert", str(EXAMPLES_DIR / "alert_bruteforce_compromise.txt"),
            "--logs", str(EXAMPLES_DIR / "sample_auth.log"),
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "CRITICAL" in captured.out
    assert "offline mode" in captured.out


def test_cli_investigate_benign_alert_exits_0(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    exit_code = main(["investigate", "--alert", str(EXAMPLES_DIR / "alert_benign_login.txt")])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "LOW" in captured.out


def test_cli_writes_json_report(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out_path = tmp_path / "report.json"
    main(
        [
            "investigate",
            "--alert", str(EXAMPLES_DIR / "alert_bruteforce_compromise.txt"),
            "--logs", str(EXAMPLES_DIR / "sample_auth.log"),
            "--json-out", str(out_path),
        ]
    )
    report = json.loads(out_path.read_text())
    assert report["verdict"]["severity"] == "critical"
    assert report["mode"] == "offline"
    assert len(report["transcript"]) >= 1


def test_cli_missing_alert_file_exits_2(capsys):
    exit_code = main(["investigate", "--alert", "/nonexistent/path.txt"])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "error" in captured.err


def test_cli_fail_on_severity_threshold_can_be_raised(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    exit_code = main(
        [
            "investigate",
            "--alert", str(EXAMPLES_DIR / "alert_bruteforce_compromise.txt"),
            "--logs", str(EXAMPLES_DIR / "sample_auth.log"),
            "--fail-on-severity", "critical",
        ]
    )
    assert exit_code == 1  # this alert is critical, so it still trips even the raised bar


def test_cli_no_transcript_flag_hides_tool_calls(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    main(["investigate", "--alert", str(EXAMPLES_DIR / "alert_benign_login.txt"), "--no-transcript"])
    captured = capsys.readouterr()
    assert "Investigation transcript" not in captured.out
