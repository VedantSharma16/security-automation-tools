from pathlib import Path

from logtriage.cli import main

SAMPLE_LOG = Path(__file__).parent.parent / "sample_data" / "auth.log"


def test_cli_analyze_runs_end_to_end(capsys):
    exit_code = main(["analyze", str(SAMPLE_LOG), "--year", "2026"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "alert(s) triggered" in captured.out
    assert "Brute-force" in captured.out
    assert "203.0.113.5" in captured.out


def test_cli_analyze_json_output_is_valid_json(capsys):
    import json

    exit_code = main(["analyze", str(SAMPLE_LOG), "--year", "2026", "--json"])
    captured = capsys.readouterr()

    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["event_count"] > 0
    assert any(alert["type"] == "brute_force" for alert in payload["alerts"])
    assert "iocs" in payload
