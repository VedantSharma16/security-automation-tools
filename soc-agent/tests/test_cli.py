import json
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MALICIOUS = os.path.join(PROJECT_ROOT, "examples", "sample_incident_malicious.json")
BENIGN = os.path.join(PROJECT_ROOT, "examples", "sample_incident_benign.json")


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


def test_cli_human_output_on_malicious_incident():
    result = _run_cli("--file", MALICIOUS)
    assert result.returncode == 0
    assert "Severity: CRITICAL" in result.stdout or "Severity: HIGH" in result.stdout
    assert "185.220.101.7" in result.stdout


def test_cli_json_output_is_valid_json():
    result = _run_cli("--file", MALICIOUS, "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["severity"] in {"low", "medium", "high", "critical"}
    assert payload["incident"]["incident_id"] == "INC-2041"
    assert len(payload["steps"]) > 0


def test_cli_benign_incident_is_low_severity_and_short_transcript():
    result = _run_cli("--file", BENIGN, "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["severity"] == "low"
    assert all(step["tool"] != "attack_technique_lookup" for step in payload["steps"])


def test_cli_errors_on_missing_file():
    result = _run_cli("--file", os.path.join(PROJECT_ROOT, "examples", "does_not_exist.json"))
    assert result.returncode != 0


def test_cli_handles_empty_stdin_gracefully():
    result = subprocess.run(
        [sys.executable, "-m", "soc_agent.cli"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0
    assert "Severity: LOW" in result.stdout
