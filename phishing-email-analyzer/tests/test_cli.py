import json
import subprocess
import sys
from pathlib import Path

from phishscope.cli import main

ROOT = Path(__file__).parent.parent
FIX = Path(__file__).parent / "fixtures"


def test_markdown_report(capsys):
    assert main(["analyze", str(FIX / "credential_phish.eml")]) == 0
    out = capsys.readouterr().out
    assert "**Verdict:** `MALICIOUS`" in out
    assert "hxxp://paypa1-secure[.]com" in out
    assert "http://paypa1-secure.com" not in out  # nothing live in the markdown


def test_json_report_multiple_files(capsys):
    main(["analyze", str(FIX / "benign_notification.eml"), str(FIX / "malware_attachment.eml"), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert [r["verdict"] for r in data] == ["LIKELY_BENIGN", "MALICIOUS"]


def test_iocs_format(capsys):
    main(["analyze", str(FIX / "malware_attachment.eml"), "--format", "iocs"])
    data = json.loads(capsys.readouterr().out)
    (iocs,) = data.values()
    assert len(iocs["sha256"]) == 2


def test_exit_codes():
    assert main(["analyze", str(FIX / "benign_notification.eml"), "--exit-code"]) == 0
    assert main(["analyze", str(FIX / "malware_attachment.eml"), "--exit-code"]) == 3


def test_custom_brands_file(tmp_path, capsys):
    brands = tmp_path / "brands.json"
    brands.write_text(json.dumps({"github": ["github.com"]}))
    eml = tmp_path / "x.eml"
    eml.write_bytes(b"From: GitHub <noreply@github-security.com>\r\nSubject: x\r\n\r\nhi")
    main(["analyze", str(eml), "--brands", str(brands), "--format", "json"])
    rules = {f["rule"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert {"header.lookalike_sender", "header.display_name_brand"} <= rules


def test_missing_file_errors(capsys):
    assert main(["analyze", "does-not-exist.eml"]) == 1


def test_module_entrypoint_subprocess(tmp_path):
    out = tmp_path / "r.json"
    proc = subprocess.run(
        [sys.executable, "-m", "phishscope", "analyze", str(FIX / "ai_prompt_injection.eml"),
         "--format", "json", "--out", str(out)],
        check=False, cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(out.read_text())["verdict"] == "MALICIOUS"
