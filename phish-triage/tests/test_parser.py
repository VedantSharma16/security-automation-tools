from pathlib import Path

from phishtriage.parser import parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_headers_and_addresses():
    msg = parse_file(FIXTURES / "phishing_paypal.eml")
    assert msg.subject == "Urgent: Verify your account immediately"
    assert msg.from_display == "PayPal Support"
    assert msg.from_addr == "security@paypa1-verify.com"
    assert msg.reply_to_addr == "support@paypal-billing-secure.net"
    assert msg.return_path_addr == "bounce@paypa1-verify.com"
    assert msg.to_addrs == ["victim@example.com"]


def test_parses_multipart_body_text_and_html():
    msg = parse_file(FIXTURES / "phishing_paypal.eml")
    assert "unusual login activity" in msg.body_text.lower()
    assert "<a href=" in msg.body_html.lower()


def test_parses_attachment_metadata():
    msg = parse_file(FIXTURES / "phishing_paypal.eml")
    assert len(msg.attachments) == 1
    assert msg.attachments[0].filename == "invoice.pdf.exe"
    assert msg.attachments[0].size_bytes > 0


def test_email_without_attachments_has_empty_list():
    msg = parse_file(FIXTURES / "benign_newsletter.eml")
    assert msg.attachments == []


def test_email_without_reply_to_returns_empty_string():
    msg = parse_file(FIXTURES / "suspicious_shortlink.eml")
    assert msg.reply_to_addr == ""
    assert msg.auth_results_raw == ""
