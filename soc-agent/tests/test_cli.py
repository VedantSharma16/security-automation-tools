import json
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
C2_ALERT = os.path.join(PROJECT_ROOT, "examples", "alert_c2_beacon.json")
BENIGN_ALERT = os.path.join(PROJECT_ROOT, "examples", "alert_benign_login.json")


def _run_cli(*args):
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    env["PYTHONPATH"] = PROJECT_ROOT
    result = subprocess.run(
        [sys.executable, "-m", "soc_agent.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    return result


def test_cli_markdown_output_on_c2_alert():
    result = _run_cli("--alert", C2_ALERT)
    assert result.returncode == 0
    assert "MALICIOUS" in result.stdout
    assert "203.0.113.55" in result.stdout


def test_cli_json_output_is_valid_json():
    result = _run_cli("--alert", C2_ALERT, "--format", "json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["verdict"] == "malicious"
    assert payload["mode"] == "offline"


def test_cli_benign_alert_produces_benign_verdict():
    result = _run_cli("--alert", BENIGN_ALERT, "--format", "json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["verdict"] == "benign"


def test_cli_errors_on_missing_alert_file():
    result = _run_cli("--alert", os.path.join(PROJECT_ROOT, "examples", "does_not_exist.json"))
    assert result.returncode != 0
    assert "not found" in result.stderr


def test_cli_errors_on_invalid_json():
    bad_path = os.path.join(PROJECT_ROOT, "examples", "not_json.json")
    with open(bad_path, "w") as f:
        f.write("{not valid json")
    try:
        result = _run_cli("--alert", bad_path)
        assert result.returncode != 0
        assert "invalid JSON" in result.stderr
    finally:
        os.remove(bad_path)
