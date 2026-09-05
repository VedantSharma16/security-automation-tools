import json
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_QUEUE = os.path.join(PROJECT_ROOT, "examples", "sample_alerts.json")


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


def test_cli_triages_full_queue_human_output():
    result = _run_cli("--queue", SAMPLE_QUEUE)
    assert result.returncode == 0
    assert "ALT-1001" in result.stdout
    assert "ALT-1004" in result.stdout
    assert "ESCALATE" in result.stdout


def test_cli_triages_single_alert_by_id():
    result = _run_cli("--queue", SAMPLE_QUEUE, "--alert-id", "ALT-1003")
    assert result.returncode == 0
    assert "ALT-1003" in result.stdout
    assert "ALT-1001" not in result.stdout
    assert "CLOSE" in result.stdout


def test_cli_json_output_is_valid_and_covers_every_alert():
    result = _run_cli("--queue", SAMPLE_QUEUE, "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert {r["alert_id"] for r in payload} == {"ALT-1001", "ALT-1002", "ALT-1003", "ALT-1004"}
    assert all(r["backend"] == "deterministic" for r in payload)


def test_cli_errors_on_unknown_alert_id():
    result = _run_cli("--queue", SAMPLE_QUEUE, "--alert-id", "does-not-exist")
    assert result.returncode != 0
