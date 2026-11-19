import json
import subprocess
import sys
from pathlib import Path

from helpers import FIXTURES

ROOT = Path(__file__).parent.parent


def run(*args):
    return subprocess.run(
        [sys.executable, "-m", "phishscope.cli", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


def test_markdown_single_file():
    r = run("analyze", str(FIXTURES / "credential_phish.eml"))
    assert r.returncode == 0
    assert r.stdout.startswith("# Phishing Triage Report: MALICIOUS")


def test_json_output_to_file(tmp_path):
    out = tmp_path / "r.json"
    r = run("analyze", str(FIXTURES / "legit_newsletter.eml"), "--format", "json", "--out", str(out))
    assert r.returncode == 0
    assert json.loads(out.read_text())["summary"]["verdict"] == "clean"


def test_directory_table_and_fail_on():
    r = run("analyze", str(FIXTURES), "--format", "table",
            "--protect-domain", "acme-corp.com", "--fail-on", "likely_phishing")
    assert r.returncode == 2
    lines = r.stdout.strip().splitlines()
    assert lines[0].startswith("VERDICT") and len(lines) == 6


def test_fail_on_not_triggered_by_clean_mail():
    r = run("analyze", str(FIXTURES / "legit_newsletter.eml"), "--fail-on", "suspicious")
    assert r.returncode == 0


def test_missing_path():
    r = run("analyze", "does-not-exist.eml")
    assert r.returncode == 1 and "no such file" in r.stderr
