import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "examples" / "alert_cnc_beacon.json"


def _run_cli(*args, env=None):
    import os

    full_env = dict(os.environ)
    full_env.pop("ANTHROPIC_API_KEY", None)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "soc_agent.cli", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=full_env,
    )


def test_cli_human_output_reports_malicious_verdict():
    result = _run_cli("--file", str(EXAMPLE))
    assert result.returncode == 0
    assert "offline deterministic planner" in result.stdout
    assert "MALICIOUS" in result.stdout
    assert "Investigation trace" in result.stdout


def test_cli_json_output_is_valid_and_structured():
    result = _run_cli("--file", str(EXAMPLE), "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["alert"]["alert_id"] == "ALERT-2026-0142"
    assert payload["verdict"]["verdict"] == "malicious"
    assert payload["mode"] == "offline"
    assert len(payload["trace"]) > 0


def test_cli_reads_alert_from_stdin():
    import os

    alert_json = EXAMPLE.read_text(encoding="utf-8")
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    result = subprocess.run(
        [sys.executable, "-m", "soc_agent.cli", "--json"],
        cwd=REPO_ROOT,
        input=alert_json,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["verdict"]["verdict"] == "malicious"


def test_cli_benign_example_reports_benign():
    result = _run_cli("--file", str(REPO_ROOT / "examples" / "alert_benign_login.json"), "--json")
    payload = json.loads(result.stdout)
    assert payload["verdict"]["verdict"] == "benign"
