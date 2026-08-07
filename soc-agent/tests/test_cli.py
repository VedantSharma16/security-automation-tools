import json
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_ALERT = os.path.join(PROJECT_ROOT, "examples", "sample_alert.txt")


def _run_cli(*args, stdin_text=None):
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    env["PYTHONPATH"] = PROJECT_ROOT
    return subprocess.run(
        [sys.executable, "-m", "soc_agent.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=env,
        input=stdin_text,
        stdin=None if stdin_text is not None else subprocess.DEVNULL,
    )


def test_cli_human_output_on_sample_alert():
    result = _run_cli("--file", SAMPLE_ALERT)
    assert result.returncode == 0
    assert "Verdict:" in result.stdout
    assert "Severity:" in result.stdout
    assert "offline deterministic" in result.stdout
    assert "185.220.101.1" in result.stdout


def test_cli_json_output_is_valid_and_complete():
    result = _run_cli("--file", SAMPLE_ALERT, "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["severity"] in {"low", "medium", "high", "critical"}
    assert payload["verdict"] in {"malicious", "suspicious", "benign", "inconclusive"}
    assert len(payload["steps"]) > 0


def test_cli_no_trace_hides_steps():
    result = _run_cli("--file", SAMPLE_ALERT, "--no-trace")
    assert result.returncode == 0
    assert "Investigation trace" not in result.stdout
    assert "Summary:" in result.stdout


def test_cli_reads_from_stdin():
    result = _run_cli(stdin_text="Beacon to 185.220.101.1 observed.")
    assert result.returncode == 0
    assert "185.220.101.1" in result.stdout


def test_cli_errors_on_missing_file():
    result = _run_cli("--file", os.path.join(PROJECT_ROOT, "examples", "does_not_exist.txt"))
    assert result.returncode != 0


def test_cli_handles_empty_stdin_gracefully():
    result = _run_cli(stdin_text="")
    assert result.returncode == 0
    assert "INCONCLUSIVE" in result.stdout
