from pathlib import Path

import pytest

from phishtriage.cli import analyze, main
from phishtriage.detectors import lookalike_of, registrable
from phishtriage.models import Finding
from phishtriage.parser import parse_auth_results
from phishtriage.scoring import score

FIX = Path(__file__).parent / "fixtures"


def run(name):
    return analyze((FIX / name).read_bytes())


def rules(findings):
    return {f.rule for f in findings}


def test_phish_detected():
    p, findings, risk, verdict = run("phish.eml")
    assert verdict == "malicious"
    assert risk >= 70
    r = rules(findings)
    assert {"reply_to_mismatch", "return_path_mismatch", "display_name_spoof", "lookalike_sender_domain",
            "spf_fail", "dmarc_fail", "ip_url", "link_text_mismatch", "url_shortener",
            "double_extension", "urgency_language", "credential_lure"} <= r


def test_benign_clean():
    p, findings, risk, verdict = run("benign.eml")
    assert findings == [] and verdict == "clean" and risk == 0


def test_parser_extracts_fields():
    p, *_ = run("phish.eml")
    assert p.from_addr == "service@paypa1-secure.top"
    assert p.auth["spf"] == "fail" and p.auth["dmarc"] == "fail"
    assert p.attachments[0].filename == "invoice.pdf.exe" and len(p.attachments[0].sha256) == 64
    assert any(l.text == "https://www.paypal.com/signin" for l in p.links)


def test_auth_first_header_wins():
    assert parse_auth_results(["x; spf=pass", "y; spf=fail"])["spf"] == "pass"


@pytest.mark.parametrize("domain,expected", [
    ("paypa1.com", "paypal.com"), ("paypal-secure.net", "paypal.com"), ("rnicrosoft.com", "microsoft.com"),
    ("paypal.com", None), ("mail.google.com", None), ("example.org", None), ("amazon.co.uk", None),
])
def test_lookalike(domain, expected):
    assert lookalike_of(domain) == expected


def test_registrable():
    assert registrable("a.b.example.co.uk") == "example.co.uk"
    assert registrable("mail.example.com") == "example.com"


def test_score_bounds():
    assert score([])[1] == "clean"
    assert score([Finding("x", "critical", "t", "d")])[1] == "malicious"
    assert score([Finding("x", "high", "t", "d")] * 2)[0] == 60
    assert score([Finding("x", "critical", "t", "d")] * 5)[0] == 100


def test_cli_exit_codes_and_json(capsys):
    assert main([str(FIX / "benign.eml")]) == 0
    assert main([str(FIX / "phish.eml"), "--json"]) == 3
    out = capsys.readouterr().out
    assert '"verdict": "malicious"' in out and "203.0.113.50" in out
    assert main(["/nonexistent.eml"]) == 2
