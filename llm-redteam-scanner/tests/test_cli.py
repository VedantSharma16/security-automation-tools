import json
import os
import subprocess
import sys

from llm_redteam.attacks import ATTACKS

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_cli(*args):
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    env["PYTHONPATH"] = PROJECT_ROOT
    result = subprocess.run(
        [sys.executable, "-m", "llm_redteam.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    return result


def test_scan_vulnerable_target_human_output():
    result = _run_cli("scan", "--target", "demo-vulnerable")
    assert result.returncode == 1  # critical/high severity exits non-zero
    assert "Overall risk: CRITICAL" in result.stdout
    assert "heuristic-only" in result.stdout


def test_scan_hardened_target_human_output():
    result = _run_cli("scan", "--target", "demo-hardened")
    assert result.returncode == 0
    assert "Overall risk: LOW" in result.stdout


def test_scan_json_output_is_valid_json():
    result = _run_cli("scan", "--target", "demo-vulnerable", "--json")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["severity"] == "critical"
    assert payload["target"] == "demo-vulnerable"
    assert payload["vulnerable_count"] == payload["total_attacks"]


def test_scan_category_filter():
    result = _run_cli("scan", "--target", "demo-vulnerable", "--category", "LLM06", "--json")
    payload = json.loads(result.stdout)
    assert all(f["category"] == "LLM06" for f in payload["findings"])
    assert payload["total_attacks"] < 12


def test_scan_live_without_system_prompt_file_errors():
    result = _run_cli("scan", "--target", "live")
    assert result.returncode != 0


def test_list_attacks_lists_every_attack_id():
    result = _run_cli("list-attacks")
    assert result.returncode == 0
    for attack in ATTACKS:
        assert attack.id in result.stdout
