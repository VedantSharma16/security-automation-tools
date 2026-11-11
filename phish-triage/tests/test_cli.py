import json
import subprocess
import sys
from pathlib import Path

from phishtriage.cli import main

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


def test_analyze_markdown(capsys):
    assert main(["analyze", str(SAMPLES / "phish_bec_giftcard.eml")]) == 0
    out = capsys.readouterr().out
    assert "MALICIOUS" in out and "CNT-BEC" in out


def test_fail_on_exit_codes():
    assert main(["analyze", str(SAMPLES / "phish_bec_giftcard.eml"), "--format", "json",
                 "--fail-on", "malicious"]) == 2
    assert main(["analyze", str(SAMPLES / "benign_paypal_receipt.eml"), "--format", "json",
                 "--fail-on", "suspicious"]) == 0


def test_directory_json_and_out_file(tmp_path):
    out = tmp_path / "r.json"
    assert main(["analyze", str(SAMPLES), "--format", "json", "--out", str(out)]) == 0
    reports = json.loads(out.read_text())
    assert len(reports) == len(list(SAMPLES.glob("*.eml")))


def test_csv(capsys):
    main(["analyze", str(SAMPLES / "phish_invoice_double_ext.eml"), "--format", "csv"])
    out = capsys.readouterr().out
    assert out.startswith("type,value,verdict,source") and "sha256," in out


def test_missing_path(capsys):
    assert main(["analyze", "does-not-exist.eml"]) == 1


def test_eval_min_recall(capsys):
    assert main(["eval", str(SAMPLES), "--min-recall", "1.0"]) == 0
    assert "precision=" in capsys.readouterr().out


def test_module_entrypoint_subprocess():
    proc = subprocess.run([sys.executable, "-m", "phishtriage.cli", "eval", str(SAMPLES), "--json"],
                          capture_output=True, text=True, cwd=ROOT, check=True)
    assert json.loads(proc.stdout)["confusion_matrix"]["fn"] == 0
