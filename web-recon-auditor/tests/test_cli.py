import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def run_cli(*args, env_extra=None):
    import os

    env = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT)}
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "webrecon.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )


def test_refuses_to_scan_without_authorization():
    result = run_cli("example.com")
    assert result.returncode == 2
    assert "authorized" in result.stderr.lower()


def test_webrecon_authorized_env_var_is_accepted(fixture_server):
    base_url, _ = fixture_server
    result = run_cli(base_url, "--format", "json", env_extra={"WEBRECON_AUTHORIZED": "1"})
    assert result.returncode in (0, 1)
    report = json.loads(result.stdout)
    assert report["target"].startswith("http://127.0.0.1")


def test_authorized_flag_runs_full_scan_against_local_server(fixture_server):
    base_url, routes = fixture_server
    routes[""] = (200, {"Server": "Apache/2.4.1"}, "<html>home</html>")

    result = run_cli(base_url, "--authorized", "--format", "json")

    assert result.returncode == 1  # findings were raised
    report = json.loads(result.stdout)
    ids = {f["id"] for f in report["findings"]}
    assert "missing-csp" in ids
    assert "banner-disclosure-server" in ids


def test_out_file_writes_report_to_disk(fixture_server, tmp_path):
    base_url, _ = fixture_server
    out_path = tmp_path / "report.md"

    result = run_cli(base_url, "--authorized", "--format", "markdown", "--out", str(out_path))

    assert result.returncode in (0, 1)
    assert out_path.exists()
    assert "Attack Surface Report" in out_path.read_text()
    assert str(out_path) in result.stdout
