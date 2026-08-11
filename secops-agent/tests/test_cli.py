import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
EXAMPLES = PROJECT_ROOT / "examples"


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "secops_agent.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )


def test_cli_investigate_json_output_flags_malicious_indicator():
    result = run_cli(
        "investigate",
        "--query",
        "Investigate brute force on db-prod-01 from 203.0.113.77",
        "--log",
        str(EXAMPLES / "sample_investigation.log"),
        "--format",
        "json",
    )
    assert result.returncode == 2, result.stderr  # malicious verdict exit code
    payload = json.loads(result.stdout)
    assert payload["verdict"].startswith("malicious")
    assert any(step["tool"] == "lookup_ioc" for step in payload["trace"])


def test_cli_investigate_text_output_on_clean_query():
    result = run_cli("investigate", "--query", "General status check, nothing specific")
    assert result.returncode == 0, result.stderr
    assert "Verdict: no evidence gathered" in result.stdout


def test_cli_errors_cleanly_on_missing_log_file():
    result = run_cli("investigate", "--query", "x", "--log", str(EXAMPLES / "does_not_exist.log"))
    assert result.returncode == 1
    assert "no such file" in result.stderr


def test_cli_respects_max_iterations_budget():
    result = run_cli(
        "investigate",
        "--query",
        "Investigate 203.0.113.77 on db-prod-01, technique T1110",
        "--log",
        str(EXAMPLES / "sample_investigation.log"),
        "--max-iterations",
        "1",
        "--format",
        "json",
    )
    payload = json.loads(result.stdout)
    assert len(payload["trace"]) == 1
    assert "budget" in payload["final_report"]
