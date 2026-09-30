import json
from pathlib import Path

from phishtriage.analyzers import check_urls, check_attachments, check_auth
from phishtriage.cli import main
from phishtriage.models import Attachment, ParsedEmail, Url
from phishtriage.parser import parse_file
from phishtriage.scoring import assess

FX = Path(__file__).parent / "fixtures"


def rules(findings):
    return {f.rule for f in findings}


def test_parse_phish_fields():
    p = parse_file(str(FX / "phish.eml"))
    assert p.from_addr == "helpdesk@micros0ft-secure.xyz"
    assert p.reply_to == "collect@freemail-drop.com"
    assert [a.filename for a in p.attachments] == ["invoice.pdf.exe"]
    assert any(u.host == "192.0.2.10" and "microsoft.com" in u.text for u in p.urls)


def test_phish_is_malicious():
    v = assess(parse_file(str(FX / "phish.eml")))
    assert v.label == "MALICIOUS" and v.score >= 70
    r = rules(v.findings)
    assert {"auth.dmarc_fail", "sender.reply_to_mismatch", "url.ip_host",
            "url.text_href_mismatch", "url.shortener", "attachment.dangerous",
            "sender.brand_impersonation"} <= r
    assert v.findings[0].severity == "critical"


def test_clean_is_clean():
    v = assess(parse_file(str(FX / "clean.eml")))
    assert v.label == "CLEAN" and v.findings == []


def test_lookalike_and_punycode():
    p = ParsedEmail(urls=[Url("https://paypa1.com/x", host="paypa1.com"),
                          Url("https://xn--pypal-4ve.com", host="xn--pypal-4ve.com")])
    r = rules(check_urls(p))
    assert "url.lookalike_domain" in r and "url.punycode" in r


def test_real_brand_domain_not_lookalike():
    p = ParsedEmail(urls=[Url("https://www.microsoft.com/", host="www.microsoft.com")])
    assert "url.lookalike_domain" not in rules(check_urls(p))


def test_userinfo_url():
    p = ParsedEmail(urls=[Url("https://google.com@evil.example/x", host="evil.example")])
    assert "url.userinfo" in rules(check_urls(p))


def test_attachment_severity():
    dbl = check_attachments(ParsedEmail(attachments=[Attachment("a.docx.js", "x")]))
    assert dbl[0].severity == "critical"
    mac = check_attachments(ParsedEmail(attachments=[Attachment("a.xlsm", "x")]))
    assert mac[0].rule == "attachment.macro"
    assert check_attachments(ParsedEmail(attachments=[Attachment("a.pdf", "x")])) == []


def test_missing_auth_low():
    assert rules(check_auth(ParsedEmail())) == {"auth.missing"}


def test_received_spf_softfail():
    p = ParsedEmail(received_spf="softfail (domain not designated)")
    assert "auth.spf_fail" in rules(check_auth(p))


def test_cli_json_and_exit_code(capsys):
    rc = main([str(FX / "phish.eml"), "--json", "--fail-on", "MALICIOUS"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 2 and out["label"] == "MALICIOUS"
    assert main([str(FX / "clean.eml"), "--fail-on", "SUSPICIOUS"]) == 0


def test_cli_missing_file():
    assert main(["/nonexistent.eml"]) == 1
