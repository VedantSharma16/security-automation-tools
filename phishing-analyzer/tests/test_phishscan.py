import subprocess
import sys
from pathlib import Path

from phishscan.parser import parse_bytes
from phishscan.scoring import analyze, label_for

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


def load(name):
    return parse_bytes((FIX / name).read_bytes())


def rules(name):
    return {f.rule for f in analyze(load(name)).findings}


def test_parser_extracts_structure():
    e = load("phish.eml")
    assert e.from_addr == "service@paypa1-secure.xyz"
    assert e.attachments[0].filename == "invoice.pdf.exe"
    assert {l.href for l in e.links} >= {"http://192.168.5.9/login", "https://bit.ly/3abc"}


def test_phish_detects_expected_rules():
    r = rules("phish.eml")
    assert {"spf_fail", "dmarc_fail", "reply_to_mismatch", "display_name_spoof", "ip_url",
            "url_shortener", "link_text_mismatch", "double_extension", "urgency_language"} <= r


def test_phish_is_malicious_clean_is_clean():
    assert analyze(load("phish.eml")).label == "MALICIOUS"
    v = analyze(load("clean.eml"))
    assert v.label == "CLEAN" and v.findings == []


def test_score_capped_and_deduplicated():
    v = analyze(load("phish.eml"))
    assert v.score <= 100


def test_label_thresholds():
    assert [label_for(s) for s in (0, 15, 40, 70)] == ["CLEAN", "LOW_RISK", "SUSPICIOUS", "MALICIOUS"]


def test_punycode_and_userinfo_urls():
    raw = (b"From: a@b.com\nSubject: x\nContent-Type: text/plain\n\n"
           b"http://xn--pypal-4ve.com/a http://paypal.com@evil.org/x")
    r = {f.rule for f in analyze(parse_bytes(raw)).findings}
    assert {"punycode_domain", "userinfo_url"} <= r


def test_macro_attachment():
    raw = (b"From: a@b.com\nSubject: x\nContent-Type: multipart/mixed; boundary=B\n\n--B\n"
           b"Content-Type: text/plain\n\nhi\n--B\nContent-Disposition: attachment; filename=q.xlsm\n"
           b"Content-Type: application/vnd.ms-excel\n\nAA\n--B--\n")
    assert "macro_attachment" in {f.rule for f in analyze(parse_bytes(raw)).findings}


def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "phishscan.cli", *args], cwd=ROOT,
                          capture_output=True, text=True)


def test_cli_json_and_fail_on():
    r = run_cli(str(FIX / "phish.eml"), "--format", "json", "--fail-on", "70")
    assert r.returncode == 2 and '"MALICIOUS"' in r.stdout
    assert run_cli(str(FIX / "clean.eml"), "--fail-on", "40").returncode == 0


def test_cli_missing_file():
    assert run_cli("nope.eml").returncode == 1
