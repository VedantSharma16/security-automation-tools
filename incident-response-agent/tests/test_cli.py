import json
from pathlib import Path

from agent.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_cli_investigate_markdown(capsys, monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    exit_code = main(["investigate", str(EXAMPLES / "alert_malicious_web01.json")])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "MALICIOUS" in out
    assert "203.0.113.55" in out


def test_cli_investigate_json(capsys, monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    exit_code = main(
        ["investigate", str(EXAMPLES / "alert_benign_ws-jdoe.json"), "--format", "json"]
    )
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert exit_code == 0
    assert payload["verdict"] == "benign"


def test_cli_investigate_writes_to_file(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out_file = tmp_path / "report.md"
    exit_code = main(
        [
            "investigate",
            str(EXAMPLES / "alert_malicious_web01.json"),
            "--out",
            str(out_file),
        ]
    )

    assert exit_code == 0
    assert out_file.exists()
    assert "MALICIOUS" in out_file.read_text(encoding="utf-8")


def test_cli_missing_alert_file(capsys) -> None:
    exit_code = main(["investigate", "/no/such/alert.json"])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "no such file" in err
