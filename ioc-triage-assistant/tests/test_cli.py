import json
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_ALERT = os.path.join(PROJECT_ROOT, "examples", "sample_alert.txt")


def _run_cli(*args):
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    env["PYTHONPATH"] = PROJECT_ROOT
    result = subprocess.run(
        [sys.executable, "-m", "ioc_triage.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    return result


def test_cli_human_output_on_sample_alert():
    result = _run_cli("--file", SAMPLE_ALERT)
    assert result.returncode == 0
    assert "Severity:" in result.stdout
    assert "185.220.101.1" in result.stdout


def test_cli_json_output_is_valid_json():
    result = _run_cli("--file", SAMPLE_ALERT, "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["severity"] in {"low", "medium", "high", "critical"}
    assert any(i["value"] == "185.220.101.1" for i in payload["indicators"])


def test_cli_errors_on_missing_file():
    result = _run_cli("--file", os.path.join(PROJECT_ROOT, "examples", "does_not_exist.txt"))
    assert result.returncode != 0


def test_cli_handles_empty_stdin_gracefully():
    result = subprocess.run(
        [sys.executable, "-m", "ioc_triage.cli"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0
    assert "Severity: LOW" in result.stdout
