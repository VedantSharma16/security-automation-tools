import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_ALERT = PROJECT_ROOT / "examples" / "sample_alert.txt"


def _cli_env() -> dict:
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    return env


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "agentic_soc.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=_cli_env(),
    )


def test_cli_human_output_on_sample_alert():
    result = _run_cli("--file", str(SAMPLE_ALERT))
    assert result.returncode == 0
    assert "Verdict: MALICIOUS" in result.stdout
    assert "offline deterministic planner" in result.stdout


def test_cli_json_output_is_valid_and_matches_schema():
    result = _run_cli("--file", str(SAMPLE_ALERT), "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["verdict"]["verdict"] == "malicious"
    assert payload["llm_backed"] is False
    assert payload["steps_used"] == len(payload["steps"])


def test_cli_errors_on_missing_file():
    result = _run_cli("--file", str(PROJECT_ROOT / "examples" / "does_not_exist.txt"))
    assert result.returncode != 0


def test_cli_reads_from_stdin():
    result = subprocess.run(
        [sys.executable, "-m", "agentic_soc.cli"],
        cwd=PROJECT_ROOT,
        input="Routine login from a known corporate IP, nothing unusual.",
        capture_output=True,
        text=True,
        env=_cli_env(),
    )
    assert result.returncode == 0
    assert "Verdict: BENIGN" in result.stdout


def test_cli_handles_empty_stdin_gracefully():
    result = subprocess.run(
        [sys.executable, "-m", "agentic_soc.cli"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=_cli_env(),
    )
    assert result.returncode == 0
    assert "Verdict: BENIGN" in result.stdout
