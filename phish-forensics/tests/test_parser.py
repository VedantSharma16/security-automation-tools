from pathlib import Path

from phish_forensics.parser import parse_eml

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_parses_basic_headers():
    email = parse_eml(FIXTURES / "benign_newsletter.eml")
    assert email.subject == "Your Example Weekly digest is here"
    assert email.from_addr == "news@example.com"
    assert email.from_domain == "example.com"
    assert email.from_display_name == "Example Weekly Newsletter"


def test_extracts_reply_to_and_return_path_domains():
    email = parse_eml(FIXTURES / "phishing_paypal_bec.eml")
    assert email.from_domain == "paypa1-support.com"
    assert email.reply_to_domain == "totally-not-evil.ru"
    assert email.return_path_domain == "totally-not-evil.ru"


def test_extracts_bodies_and_html_links():
    email = parse_eml(FIXTURES / "phishing_paypal_bec.eml")
    assert "unusual activity" in email.body_text.lower()
    assert email.body_html
    hrefs = [link.href for link in email.html_links]
    assert "http://203.0.113.77/login" in hrefs
    assert any("bit.ly" in href for href in hrefs)


def test_extracts_attachment_metadata_and_hash():
    email = parse_eml(FIXTURES / "phishing_paypal_bec.eml")
    assert len(email.attachments) == 1
    attachment = email.attachments[0]
    assert attachment.filename == "invoice.pdf.exe"
    assert len(attachment.sha256) == 64
    assert attachment.size > 0


def test_extracts_received_and_auth_results_headers():
    email = parse_eml(FIXTURES / "phishing_paypal_bec.eml")
    assert len(email.received_headers) == 1
    assert len(email.auth_results_headers) == 1
    assert "spf=fail" in email.auth_results_headers[0]


def test_no_attachments_on_benign_email():
    email = parse_eml(FIXTURES / "benign_newsletter.eml")
    assert email.attachments == []


def test_parse_eml_accepts_raw_bytes():
    raw = (FIXTURES / "benign_newsletter.eml").read_bytes()
    email = parse_eml(raw)
    assert email.from_addr == "news@example.com"
