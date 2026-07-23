import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "phishtriage.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )


def test_cli_scan_json_output_on_phishing_fixture():
    result = run_cli("scan", str(FIXTURES / "phishing_paypal.eml"), "--format", "json")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["summary"]["verdict"] == "likely_phishing"
    assert report["narrative"]  # template summarizer fills this in even without --llm


def test_cli_scan_markdown_output_on_clean_fixture():
    result = run_cli("scan", str(FIXTURES / "clean_newsletter.eml"), "--format", "markdown")
    assert result.returncode == 0, result.stderr
    assert "# Phishing Triage Report" in result.stdout
    assert "No phishing indicators detected." in result.stdout


def test_cli_errors_cleanly_on_missing_file():
    result = run_cli("scan", str(FIXTURES / "does_not_exist.eml"))
    assert result.returncode == 1
    assert "no such file" in result.stderr


def test_cli_writes_to_output_file(tmp_path):
    out_file = tmp_path / "report.json"
    result = run_cli(
        "scan", str(FIXTURES / "phishing_paypal.eml"), "--format", "json", "--out", str(out_file)
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    report = json.loads(out_file.read_text())
    assert report["summary"]["total_findings"] > 0
