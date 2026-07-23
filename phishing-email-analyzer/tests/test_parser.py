from pathlib import Path

from phishtriage.parser import parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_sender_and_reply_to():
    email = parse_file(FIXTURES / "phishing_paypal.eml")
    assert email.from_display_name == "PayPal Security"
    assert email.from_address == "security@paypa1-secure.com"
    assert email.from_domain == "paypa1-secure.com"
    assert email.reply_to_address == "support@totally-legit-payments.ru"
    assert email.reply_to_domain == "totally-legit-payments.ru"


def test_parses_subject_and_date():
    email = parse_file(FIXTURES / "phishing_paypal.eml")
    assert "verify your account" in email.subject.lower()
    assert email.date is not None


def test_extracts_authentication_results_and_received():
    email = parse_file(FIXTURES / "phishing_paypal.eml")
    assert email.authentication_results_raw is not None
    assert "spf=fail" in email.authentication_results_raw
    assert len(email.received_headers) == 1


def test_extracts_html_and_bare_links():
    email = parse_file(FIXTURES / "phishing_paypal.eml")
    hrefs = {link.href for link in email.links}
    assert "http://203.0.113.44/paypal/login.php" in hrefs
    assert "http://bit.ly/pp-statement" in hrefs


def test_anchor_text_captured_for_mismatch_detection():
    email = parse_file(FIXTURES / "phishing_paypal.eml")
    cloaked = next(link for link in email.links if link.href == "http://203.0.113.44/paypal/login.php")
    assert "paypal.com" in cloaked.anchor_text


def test_extracts_attachment_metadata():
    email = parse_file(FIXTURES / "phishing_paypal.eml")
    assert len(email.attachments) == 1
    attachment = email.attachments[0]
    assert attachment.filename == "Invoice_Statement.pdf.exe"
    assert attachment.size > 0


def test_clean_email_has_no_attachments_and_matching_reply_to():
    email = parse_file(FIXTURES / "clean_newsletter.eml")
    assert email.attachments == []
    assert email.from_domain == "acme-newsletter.com"
    assert email.reply_to_domain == ""
