import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
EXAMPLES = PROJECT_ROOT / "examples"


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "webrecon.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )


def test_cli_analyze_json_output_on_wordpress_fixture():
    result = run_cli("analyze", str(EXAMPLES / "wordpress_https_capture.json"), "--format", "json")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["target"].startswith("https://blog.")
    assert any(t["name"] == "WordPress" for t in report["technologies"])
    assert report["narrative"]  # template summarizer fills this in even without --llm


def test_cli_analyze_markdown_output_on_hardened_fixture():
    result = run_cli("analyze", str(EXAMPLES / "hardened_https_capture.json"), "--format", "markdown")
    assert result.returncode == 0, result.stderr
    assert "# Web Recon Report:" in result.stdout
    assert "No issues found." in result.stdout


def test_cli_analyze_flags_expiring_cert():
    result = run_cli("analyze", str(EXAMPLES / "expiring_cert_capture.json"), "--format", "json")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    severities = {f["severity"] for f in report["tls_findings"]}
    assert severities & {"high", "critical", "medium"}


def test_cli_errors_cleanly_on_missing_fixture():
    result = run_cli("analyze", str(EXAMPLES / "does_not_exist.json"))
    assert result.returncode == 1
    assert "no such file" in result.stderr


def test_cli_errors_cleanly_on_invalid_json(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json", encoding="utf-8")
    result = run_cli("analyze", str(bad_file))
    assert result.returncode == 1
    assert "invalid JSON" in result.stderr


def test_cli_scan_rejects_unsupported_scheme_without_network():
    result = run_cli("scan", "ftp://example.test")
    assert result.returncode == 1
    assert "unsupported URL scheme" in result.stderr


def test_cli_writes_to_output_file(tmp_path):
    out_file = tmp_path / "report.json"
    result = run_cli(
        "analyze", str(EXAMPLES / "wordpress_https_capture.json"), "--format", "json", "--out", str(out_file)
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    report = json.loads(out_file.read_text())
    assert report["http"]["status_code"] == 200
