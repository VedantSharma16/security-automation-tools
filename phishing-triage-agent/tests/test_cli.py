import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
EXAMPLES = PROJECT_ROOT / "examples"


def run_cli(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)  # force offline mode regardless of the host environment
    return subprocess.run(
        [sys.executable, "-m", "phishing_agent.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )


def test_cli_flags_phishing_sample_and_exits_nonzero():
    result = run_cli("--file", str(EXAMPLES / "phishing_sample.eml"))
    assert result.returncode == 1
    assert "PHISHING" in result.stdout
    assert "offline (deterministic sweep)" in result.stdout


def test_cli_clears_benign_sample_and_exits_zero():
    result = run_cli("--file", str(EXAMPLES / "benign_sample.eml"))
    assert result.returncode == 0
    assert "BENIGN" in result.stdout


def test_cli_json_output_is_valid_and_complete():
    result = run_cli("--file", str(EXAMPLES / "phishing_sample.eml"), "--json")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["result"]["verdict"] == "phishing"
    assert len(payload["result"]["trace"]) == 6
    assert payload["email"]["from_addr"] == "alerts@paypa1-secure.com"


def test_cli_reads_from_stdin():
    raw = (EXAMPLES / "benign_sample.eml").read_bytes()
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    result = subprocess.run(
        [sys.executable, "-m", "phishing_agent.cli"],
        cwd=PROJECT_ROOT,
        input=raw,
        capture_output=True,
        env=env,
    )
    assert result.returncode == 0
    assert b"BENIGN" in result.stdout


def test_cli_errors_cleanly_on_missing_file():
    result = run_cli("--file", str(EXAMPLES / "does_not_exist.eml"))
    assert result.returncode != 0
