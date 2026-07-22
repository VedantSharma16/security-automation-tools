import json
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_INCIDENT = os.path.join(PROJECT_ROOT, "examples", "sample_incident.txt")


def _run_cli(*args, stdin_data=None):
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    env["PYTHONPATH"] = PROJECT_ROOT
    return subprocess.run(
        [sys.executable, "-m", "ir_agent.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=env,
        input=stdin_data,
    )


def test_cli_markdown_output_on_sample_incident():
    result = _run_cli("--file", SAMPLE_INCIDENT)
    assert result.returncode == 0
    assert "Severity:" in result.stdout
    assert "CRITICAL" in result.stdout
    assert "91.219.236.18" in result.stdout


def test_cli_json_output_is_valid_and_complete():
    result = _run_cli("--file", SAMPLE_INCIDENT, "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["severity"] == "critical"
    assert payload["mode"] == "offline"
    assert "T1110" in payload["attack_techniques"]


def test_cli_no_transcript_flag_omits_transcript_section():
    result = _run_cli("--file", SAMPLE_INCIDENT, "--no-transcript")
    assert "Investigation transcript" not in result.stdout


def test_cli_errors_on_missing_file():
    result = _run_cli("--file", os.path.join(PROJECT_ROOT, "examples", "does_not_exist.txt"))
    assert result.returncode != 0


def test_cli_reads_from_stdin():
    result = _run_cli(stdin_data="Routine maintenance window completed with no issues.")
    assert result.returncode == 0
    assert "LOW" in result.stdout
