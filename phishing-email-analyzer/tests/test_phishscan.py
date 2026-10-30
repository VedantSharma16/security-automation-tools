from pathlib import Path

import pytest

from phishscan.analyzer import analyze, load_message
from phishscan.attachments import analyze_attachments
from phishscan.cli import main
from phishscan.headers import auth_results
from phishscan.models import Finding
from phishscan.scoring import score
from phishscan.urls import analyze_urls, registrable

FIX = Path(__file__).parent / "fixtures"


def descs(findings):
    return " | ".join(f.description for f in findings)


def test_clean_email_is_clean():
    r = analyze(load_message(FIX / "clean.eml"))
    assert r["label"] == "clean" and r["score"] == 0


def test_phish_email_detected_end_to_end():
    r = analyze(load_message(FIX / "phish.eml"))
    assert r["label"] == "likely_phishing" and r["score"] >= 60
    text = descs([Finding(**f) for f in r["findings"]])
    for expected in ("DMARC result: fail", "Reply-To domain differs", "Display name contains",
                     "raw IP", "Link text domain differs", "Double extension", "Sender domain impersonates paypal"):
        assert expected in text
    assert r["attachments"][0]["magic"] == "Windows PE executable"


def test_auth_results_parsing():
    m = load_message(FIX / "phish.eml")
    assert auth_results(m) == {"spf": "fail", "dkim": "none", "dmarc": "fail"}


@pytest.mark.parametrize("host,expected", [("a.b.example.com", "example.com"), ("x.foo.co.uk", "foo.co.uk")])
def test_registrable(host, expected):
    assert registrable(host) == expected


def test_legit_brand_domain_not_flagged():
    assert not analyze_urls("see https://accounts.google.com/signin")


def test_homoglyph_lookalike_and_shortener_and_punycode():
    f = analyze_urls("http://micr0soft-login.com http://bit.ly/x http://xn--pple-43d.com")
    d = descs(f)
    assert "impersonates microsoft" in d and "shortener" in d and "Punycode" in d


def test_userinfo_trick():
    assert "userinfo" in descs(analyze_urls("http://paypal.com@evil.example.org/"))


def test_macro_and_archive_attachments(tmp_path):
    from email.message import EmailMessage
    m = EmailMessage()
    m.set_content("hi")
    m.add_attachment(b"PK\x03\x04", maintype="application", subtype="zip", filename="a.docm")
    m.add_attachment(b"data", maintype="application", subtype="zip", filename="b.zip")
    _, f = analyze_attachments(m)
    assert "Macro-enabled" in descs(f) and "Archive" in descs(f)


def test_score_caps_repeated_findings():
    many = [Finding("url", "high", "same") for _ in range(10)]
    assert score(many).score == 80  # capped at 2x


def test_cli_exit_codes(capsys):
    assert main([str(FIX / "clean.eml")]) == 0
    assert main([str(FIX / "phish.eml"), "--json"]) == 2
    assert '"likely_phishing"' in capsys.readouterr().out
    assert main(["/nonexistent.eml"]) == 3
