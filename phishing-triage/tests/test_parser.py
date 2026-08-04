from __future__ import annotations

import os

from phishing_triage.parser import parse_email_bytes, parse_file

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHISHING_SAMPLE = os.path.join(PROJECT_ROOT, "examples", "phishing_sample.eml")
LEGIT_SAMPLE = os.path.join(PROJECT_ROOT, "examples", "legitimate_sample.eml")


def test_parses_sender_identity():
    parsed = parse_file(PHISHING_SAMPLE)
    assert parsed.from_display == "PayPal Security Team"
    assert parsed.from_addr == "security@paypa1-support.tk"
    assert parsed.from_domain == "paypa1-support.tk"


def test_parses_reply_to():
    parsed = parse_file(PHISHING_SAMPLE)
    assert parsed.reply_to_addr == "recover-support@mail-secure-help.tk"
    assert parsed.reply_to_domain == "mail-secure-help.tk"


def test_parses_subject_and_message_id():
    parsed = parse_file(PHISHING_SAMPLE)
    assert "Suspended" in parsed.subject
    assert parsed.message_id is not None


def test_extracts_both_authentication_results_header_and_received_count():
    parsed = parse_file(PHISHING_SAMPLE)
    assert len(parsed.authentication_results_raw) == 1
    assert "spf=fail" in parsed.authentication_results_raw[0]
    assert parsed.received_count == 2


def test_extracts_plain_and_html_bodies():
    parsed = parse_file(PHISHING_SAMPLE)
    assert "unusual activity" in parsed.body_text
    assert "<p>" in parsed.body_html


def test_extracts_links_from_both_text_and_html_with_dedup_by_source():
    parsed = parse_file(PHISHING_SAMPLE)
    # Same href appears in both the text and HTML parts of this sample.
    assert len(parsed.links) == 2
    sources = {link.source for link in parsed.links}
    assert sources == {"text", "html"}
    html_link = next(link for link in parsed.links if link.source == "html")
    assert html_link.display_text == "https://www.paypal.com/verify-account"
    assert html_link.href.startswith("http://paypal.com@")


def test_extracts_attachment_metadata():
    parsed = parse_file(PHISHING_SAMPLE)
    assert len(parsed.attachments) == 1
    attachment = parsed.attachments[0]
    assert attachment.filename == "invoice.pdf.exe"
    assert attachment.size_bytes > 0


def test_legitimate_sample_has_no_attachments_and_personalized_body():
    parsed = parse_file(LEGIT_SAMPLE)
    assert parsed.attachments == ()
    assert "Alice" in parsed.body_text
    assert len(parsed.links) == 2


def test_visible_text_combines_subject_plain_and_stripped_html():
    parsed = parse_file(LEGIT_SAMPLE)
    text = parsed.visible_text
    assert "pull request" in text.lower()
    assert "<p>" not in text


def test_parse_email_bytes_matches_parse_file():
    with open(PHISHING_SAMPLE, "rb") as fh:
        data = fh.read()
    from_bytes = parse_email_bytes(data)
    from_file = parse_file(PHISHING_SAMPLE)
    assert from_bytes.from_addr == from_file.from_addr
    assert from_bytes.links == from_file.links
