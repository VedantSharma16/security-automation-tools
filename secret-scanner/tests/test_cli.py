import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent


def run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "secretscan.cli", *args],
        cwd=cwd or PROJECT_ROOT,
        capture_output=True,
        text=True,
    )


def test_scan_clean_directory_exits_zero(tmp_path):
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")

    result = run_cli("scan", str(tmp_path))

    assert result.returncode == 0
    assert "No secrets found." in result.stdout


def test_scan_leaky_directory_exits_one_with_json(tmp_path):
    (tmp_path / "settings.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

    result = run_cli("scan", str(tmp_path), "--format", "json")

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["summary"]["new_findings"] == 1
    assert report["findings"][0]["rule_id"] == "aws-access-key-id"


def test_baseline_workflow_suppresses_accepted_finding(tmp_path):
    (tmp_path / "settings.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    baseline_path = tmp_path / "baseline.json"

    baseline_result = run_cli("baseline", str(tmp_path), "--out", str(baseline_path))
    assert baseline_result.returncode == 0
    assert baseline_path.exists()

    scan_result = run_cli(
        "scan", str(tmp_path), "--baseline", str(baseline_path), "--format", "json"
    )
    assert scan_result.returncode == 0
    report = json.loads(scan_result.stdout)
    assert report["summary"]["new_findings"] == 0
    assert report["summary"]["baselined_findings"] == 1

    # A brand-new secret introduced after the baseline was cut still fails.
    (tmp_path / "other.py").write_text(
        'token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"\n'
    )
    rescan = run_cli("scan", str(tmp_path), "--baseline", str(baseline_path), "--format", "json")
    assert rescan.returncode == 1
    report2 = json.loads(rescan.stdout)
    assert report2["summary"]["new_findings"] == 1
    assert report2["summary"]["baselined_findings"] == 1


def test_scan_writes_report_to_output_file(tmp_path):
    (tmp_path / "settings.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    out_file = tmp_path / "report.txt"

    result = run_cli("scan", str(tmp_path), "--out", str(out_file))

    assert result.returncode == 1
    assert out_file.exists()
    assert "aws-access-key-id" in out_file.read_text()


def test_scan_errors_cleanly_on_missing_path():
    result = run_cli("scan", "/no/such/directory/exists")
    assert result.returncode == 2
    assert "scan failed" in result.stderr
