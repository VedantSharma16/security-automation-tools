import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "recon_agent.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_cli_blocks_public_target_without_authorization():
    result = run_cli("example.com")
    assert result.returncode == 2
    assert "authorization" in result.stderr.lower() or "authoriz" in result.stderr.lower()


def test_cli_scans_loopback_target_without_confirmation_flag():
    result = run_cli("127.0.0.1", "--wordlist", str(FIXTURES / "tiny_wordlist.txt"), "--no-color")
    assert result.returncode in (0, 1), result.stderr
    assert "Overall risk:" in result.stdout
    assert "Target: 127.0.0.1" in result.stdout


def test_cli_writes_json_report(tmp_path):
    out_file = tmp_path / "report.json"
    result = run_cli(
        "127.0.0.1",
        "--wordlist", str(FIXTURES / "tiny_wordlist.txt"),
        "--no-color",
        "--json-out", str(out_file),
    )
    assert result.returncode in (0, 1), result.stderr
    report = json.loads(out_file.read_text())
    assert report["target"] == "127.0.0.1"
    assert "overall_risk" in report
    assert "findings" in report


def test_cli_errors_cleanly_on_missing_wordlist():
    result = run_cli("127.0.0.1", "--wordlist", str(FIXTURES / "does_not_exist.txt"))
    assert result.returncode == 2
    assert "error:" in result.stderr.lower()
