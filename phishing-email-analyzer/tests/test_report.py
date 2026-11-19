import json

import pytest
from helpers import FIXTURES

from phishscope.checks import AnalysisConfig
from phishscope.parser import parse_file
from phishscope.report import analyze, defang, defang_text, to_json, to_markdown

ACME = AnalysisConfig(protected_domains=["acme-corp.com"])


def report_for(name, cfg=ACME):
    return analyze(parse_file(FIXTURES / name), cfg, source=name)


@pytest.mark.parametrize("name,verdict", [
    ("credential_phish.eml", "malicious"),
    ("bec_wire_fraud.eml", "malicious"),
    ("malware_attachment.eml", "malicious"),
    ("legit_microsoft_alert.eml", "clean"),
    ("legit_newsletter.eml", "clean"),
])
def test_fixture_verdicts(name, verdict):
    assert report_for(name)["summary"]["verdict"] == verdict


def test_bec_relies_on_protected_domain():
    # Without the org's domain configured, the homoglyph sender isn't recognised,
    # but Reply-To + payment language still makes it at least suspicious.
    r = report_for("bec_wire_fraud.eml", AnalysisConfig())
    assert "sender_lookalike_domain" not in {f["check"] for f in r["findings"]}
    assert r["summary"]["verdict"] in {"suspicious", "likely_phishing"}


def test_iocs_exclude_legitimate_and_shortener_domains():
    iocs = report_for("credential_phish.eml")["iocs"]
    assert "micros0ft-support.com" in iocs["domains"]
    assert "login.micros0ft-support.xyz" in iocs["domains"]
    assert "bit.ly" not in iocs["domains"]
    assert "https://bit.ly/3xYz9Qa" in iocs["urls"]
    assert not any("microsoftonline.com" in u for u in iocs["urls"])
    assert iocs["originating_ips"] == ["203.0.113.45"]
    assert iocs["url_ips"] == ["203.0.113.45"]


def test_freemail_reply_to_not_listed_as_blockable_domain():
    iocs = report_for("bec_wire_fraud.eml")["iocs"]
    assert iocs["domains"] == ["acme-c0rp.com"]
    assert iocs["reply_to"] == ["dana.whitfield.exec@gmail.com"]


def test_attachment_hashes_in_iocs():
    iocs = report_for("malware_attachment.eml")["iocs"]
    assert {a["filename"] for a in iocs["attachments"]} == {
        "Invoice_4471.pdf.exe", "remittance_advice.html", "terms.pdf",
    }


def test_defang():
    assert defang("http://evil.example/a") == "hxxp://evil[.]example/a"
    assert defang("x@evil.example") == "x[@]evil[.]example"


def test_defang_text_handles_embedded_indicators():
    out = defang_text("link goes to 'https://login.evil.example/x' from a@evil.example via 203.0.113.9")
    assert out == "link goes to 'hxxps://login[.]evil[.]example/x' from a[@]evil[.]example via 203[.]0[.]113[.]9"


def test_markdown_never_contains_live_malicious_urls():
    md = to_markdown(report_for("credential_phish.eml"))
    assert "micros0ft-support.xyz" not in md
    assert "http://203.0.113.45" not in md
    assert "hxxp://203[.]0[.]113[.]45/collect[.]php" in md


def test_json_round_trips():
    data = json.loads(to_json(report_for("malware_attachment.eml")))
    assert data["summary"]["highest_severity"] == "critical"
    assert all(f["mitre"].startswith("T1") for f in data["findings"])
