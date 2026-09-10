import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOC_AGENT_DIR = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "soc_agent.cli", *args],
        cwd=SOC_AGENT_DIR,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_cli_requires_evidence_or_scan_processes():
    proc = _run_cli()
    assert proc.returncode != 0
    assert "provide --evidence" in proc.stderr


def test_cli_errors_on_missing_evidence_file():
    proc = _run_cli("--evidence", "does_not_exist.txt")
    assert proc.returncode == 2
    assert "no such file" in proc.stderr


def test_cli_auth_evidence_end_to_end_json():
    proc = _run_cli("--evidence", str(FIXTURES / "auth_evidence.txt"), "--format", "json")
    assert proc.returncode == 1, proc.stderr  # findings present

    report = json.loads(proc.stdout)
    assert report["tools_run"] == ["log_triage"]
    assert report["tools_skipped"] == ["ioc_triage", "process_hunter"]
    assert report["overall_severity"] in ("low", "medium", "high", "critical")
    assert report["narrative"]


def test_cli_alert_evidence_end_to_end_markdown():
    proc = _run_cli("--evidence", str(FIXTURES / "alert_evidence.txt"), "--format", "markdown")
    assert proc.returncode == 1, proc.stderr

    assert "# SOC Triage Report" in proc.stdout
    assert "ioc_triage" in proc.stdout
    assert "Recommended actions" in proc.stdout


def test_cli_benign_evidence_is_clean():
    proc = _run_cli("--evidence", str(FIXTURES / "benign_evidence.txt"), "--format", "json")
    assert proc.returncode == 0

    report = json.loads(proc.stdout)
    assert report["total_findings"] == 0
    assert report["tools_run"] == ["ioc_triage"]


def test_cli_force_and_skip_flags_override_router():
    proc = _run_cli(
        "--evidence",
        str(FIXTURES / "auth_evidence.txt"),
        "--force-ioc",
        "--skip-log",
        "--format",
        "json",
    )
    report = json.loads(proc.stdout)
    assert report["tools_run"] == ["ioc_triage"]
    assert report["tools_skipped"] == ["log_triage", "process_hunter"]


def test_cli_out_file_writes_report(tmp_path):
    out_path = tmp_path / "report.md"
    proc = _run_cli(
        "--evidence", str(FIXTURES / "auth_evidence.txt"), "--format", "markdown", "--out", str(out_path)
    )
    assert proc.returncode == 1
    assert out_path.exists()
    assert "# SOC Triage Report" in out_path.read_text(encoding="utf-8")
    assert proc.stdout == ""
