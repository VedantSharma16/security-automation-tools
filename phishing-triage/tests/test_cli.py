from __future__ import annotations

import json
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHISHING_SAMPLE = os.path.join(PROJECT_ROOT, "examples", "phishing_sample.eml")
LEGIT_SAMPLE = os.path.join(PROJECT_ROOT, "examples", "legitimate_sample.eml")


def _run_cli(*args, stdin_bytes: bytes | None = None):
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    env["PYTHONPATH"] = PROJECT_ROOT
    return subprocess.run(
        [sys.executable, "-m", "phishing_triage.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        input=stdin_bytes,
        env=env,
    )


def test_cli_exits_1_and_flags_phishing_sample():
    result = _run_cli(PHISHING_SAMPLE, "--no-color")
    assert result.returncode == 1
    assert b"LIKELY PHISHING" in result.stdout


def test_cli_exits_0_for_legitimate_sample():
    result = _run_cli(LEGIT_SAMPLE, "--no-color")
    assert result.returncode == 0
    assert b"BENIGN" in result.stdout


def test_cli_json_output_is_valid_and_matches_verdict():
    result = _run_cli(PHISHING_SAMPLE, "--json")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["triage"]["verdict"] == "likely_phishing"
    assert payload["narrative"]


def test_cli_errors_on_missing_file():
    result = _run_cli(os.path.join(PROJECT_ROOT, "examples", "does_not_exist.eml"))
    assert result.returncode == 2
    assert b"no such file" in result.stderr


def test_cli_reads_from_stdin_when_no_file_given():
    with open(PHISHING_SAMPLE, "rb") as fh:
        data = fh.read()
    result = _run_cli("--no-color", stdin_bytes=data)
    assert result.returncode == 1
    assert b"LIKELY PHISHING" in result.stdout


def test_cli_out_flag_writes_report_to_file(tmp_path):
    out_path = tmp_path / "report.json"
    result = _run_cli(PHISHING_SAMPLE, "--json", "--out", str(out_path))
    assert result.returncode == 1
    assert out_path.exists()
    payload = json.loads(out_path.read_text())
    assert payload["triage"]["verdict"] == "likely_phishing"
