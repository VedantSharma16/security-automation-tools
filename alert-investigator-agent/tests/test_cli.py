import json
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_ALERT = os.path.join(PROJECT_ROOT, "examples", "sample_alert.json")


def _run_cli(*args):
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    env["PYTHONPATH"] = PROJECT_ROOT
    result = subprocess.run(
        [sys.executable, "-m", "investigator.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    return result


def test_cli_markdown_output_on_sample_alert():
    result = _run_cli("investigate", SAMPLE_ALERT)
    assert result.returncode == 0
    assert "# Investigation Report: EDR-20260808-0417" in result.stdout
    assert "185.220.101.45" in result.stdout


def test_cli_json_output_is_valid_json():
    result = _run_cli("investigate", SAMPLE_ALERT, "--format", "json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["verdict"] in {"true_positive", "false_positive", "needs_escalation"}
    assert payload["mode"] == "offline_planner"


def test_cli_no_llm_flag_forces_offline_planner():
    result = _run_cli("investigate", SAMPLE_ALERT, "--format", "json", "--no-llm")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["mode"] == "offline_planner"


def test_cli_writes_to_output_file(tmp_path):
    out_file = tmp_path / "report.json"
    result = _run_cli("investigate", SAMPLE_ALERT, "--format", "json", "--out", str(out_file))
    assert result.returncode == 0
    assert out_file.exists()
    payload = json.loads(out_file.read_text())
    assert payload["alert"]["alert_id"] == "EDR-20260808-0417"


def test_cli_errors_on_missing_file():
    result = _run_cli("investigate", os.path.join(PROJECT_ROOT, "examples", "does_not_exist.json"))
    assert result.returncode != 0
