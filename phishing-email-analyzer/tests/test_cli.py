import json

import pytest

from phishtriage.cli import main


@pytest.mark.parametrize("name,verdict,code", [
    ("benign_newsletter.eml", "benign", 0),
    ("credential_phish.eml", "malicious", 3),
    ("malware_attachment.eml", "malicious", 3),
    ("html_smuggling.eml", "malicious", 3),
    ("bec_invoice.eml", None, None),
])
def test_fixture_verdicts_and_exit_codes(fixtures_dir, capsys, name, verdict, code):
    rc = main(["analyze", str(fixtures_dir / name), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    if verdict is None:  # BEC: must be at least likely-phishing and flagged as BEC
        assert report["verdict"] in ("likely-phishing", "malicious")
        assert "corr_bec" in {i["id"] for i in report["indicators"]}
        assert rc >= 2
    else:
        assert report["verdict"] == verdict and rc == code


def test_batch_directory_markdown(fixtures_dir, tmp_path, capsys):
    out = tmp_path / "report.md"
    rc = main(["analyze", str(fixtures_dir), "--out", str(out), "--no-narrative"])
    text = out.read_text()
    assert text.startswith("# Phishing Triage — Batch Summary")
    assert text.count("# Phishing Triage —") == 6  # summary + 5 messages
    assert rc == 3


def test_missing_path(capsys):
    assert main(["analyze", "/nonexistent/file.eml"]) == 64
