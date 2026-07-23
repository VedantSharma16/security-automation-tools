from pathlib import Path

from phishtriage.heuristics import (
    check_attachments,
    check_authentication,
    check_brand_impersonation,
    check_links,
    check_reply_to_mismatch,
    check_urgency_language,
    run_all_heuristics,
)
from phishtriage.parser import Attachment, Link, ParsedEmail, parse_file

FIXTURES = Path(__file__).parent / "fixtures"

KNOWN_BRANDS = {"paypal": ["paypal.com"]}


def _blank_email(**overrides) -> ParsedEmail:
    base = dict(
        headers={},
        from_display_name="",
        from_address="",
        reply_to_address="",
        subject="",
        date=None,
        body_text="",
        body_html="",
        links=[],
        attachments=[],
        authentication_results_raw=None,
        received_headers=[],
    )
    base.update(overrides)
    return ParsedEmail(**base)


def test_full_pipeline_flags_known_phishing_sample():
    email = parse_file(FIXTURES / "phishing_paypal.eml")
    findings = run_all_heuristics(email)
    types = {f.type for f in findings}
    assert "auth_failure" in types
    assert "reply_to_mismatch" in types
    assert "brand_display_name_mismatch" in types
    assert "ip_literal_link" in types
    assert "url_shortener" in types
    assert "mismatched_anchor_text" in types
    assert "urgency_language" in types
    assert "dangerous_attachment" in types


def test_full_pipeline_clean_sample_has_no_findings():
    email = parse_file(FIXTURES / "clean_newsletter.eml")
    findings = run_all_heuristics(email)
    assert findings == []


def test_reply_to_mismatch_flags_different_domain():
    email = _blank_email(from_address="a@bank.com", reply_to_address="b@evil.ru")
    findings = check_reply_to_mismatch(email)
    assert len(findings) == 1
    assert findings[0].type == "reply_to_mismatch"


def test_reply_to_mismatch_ignores_matching_domain():
    email = _blank_email(from_address="a@bank.com", reply_to_address="b@bank.com")
    assert check_reply_to_mismatch(email) == []


def test_reply_to_mismatch_ignores_absent_reply_to():
    email = _blank_email(from_address="a@bank.com", reply_to_address="")
    assert check_reply_to_mismatch(email) == []


def test_brand_display_name_mismatch_detected():
    email = _blank_email(from_display_name="PayPal Support", from_address="alert@paypal-alerts.net")
    findings = check_brand_impersonation(email, known_brands=KNOWN_BRANDS)
    assert any(f.type == "brand_display_name_mismatch" for f in findings)


def test_brand_display_name_matching_domain_is_not_flagged():
    email = _blank_email(from_display_name="PayPal Support", from_address="alert@paypal.com")
    assert check_brand_impersonation(email, known_brands=KNOWN_BRANDS) == []


def test_lookalike_domain_detected_for_typosquat():
    email = _blank_email(from_display_name="Account Team", from_address="alert@paypa1.com")
    findings = check_brand_impersonation(email, known_brands=KNOWN_BRANDS)
    assert any(f.type == "lookalike_sender_domain" for f in findings)


def test_unrelated_domain_not_flagged_as_lookalike():
    email = _blank_email(from_display_name="Newsletter", from_address="hello@some-blog.com")
    assert check_brand_impersonation(email, known_brands=KNOWN_BRANDS) == []


def test_ip_literal_link_detected():
    email = _blank_email(links=[Link(href="http://192.0.2.5/login", anchor_text="login")])
    findings = check_links(email)
    assert any(f.type == "ip_literal_link" for f in findings)


def test_url_shortener_detected():
    email = _blank_email(links=[Link(href="http://bit.ly/abc123", anchor_text="click here")])
    findings = check_links(email)
    assert any(f.type == "url_shortener" for f in findings)


def test_mismatched_anchor_text_detected():
    email = _blank_email(
        links=[Link(href="http://evil.com/login", anchor_text="https://mybank.com/login")]
    )
    findings = check_links(email)
    assert any(f.type == "mismatched_anchor_text" for f in findings)


def test_plain_anchor_text_not_treated_as_mismatch():
    email = _blank_email(links=[Link(href="https://mybank.com/login", anchor_text="Click here to log in")])
    findings = check_links(email)
    assert all(f.type != "mismatched_anchor_text" for f in findings)


def test_clean_links_produce_no_findings():
    email = _blank_email(links=[Link(href="https://mybank.com/login", anchor_text="https://mybank.com/login")])
    assert check_links(email) == []


def test_urgency_language_detected():
    email = _blank_email(subject="Account will be closed", body_text="Please act now", body_html="")
    findings = check_urgency_language(email)
    assert len(findings) == 1
    assert "account will be closed" in findings[0].evidence["matched_phrases"]


def test_no_urgency_language_for_neutral_text():
    email = _blank_email(subject="Weekly digest", body_text="Here is our update", body_html="")
    assert check_urgency_language(email) == []


def test_dangerous_attachment_extension_detected():
    email = _blank_email(
        attachments=[Attachment(filename="invoice.exe", content_type="application/octet-stream", size=100)]
    )
    findings = check_attachments(email)
    assert len(findings) == 1
    assert "invoice.exe" in findings[0].evidence["attachments"]


def test_double_extension_attachment_flagged_as_masquerading():
    email = _blank_email(
        attachments=[
            Attachment(filename="Invoice_Statement.pdf.exe", content_type="application/octet-stream", size=100)
        ]
    )
    findings = check_attachments(email)
    assert findings[0].evidence["masquerading_as_document"] == ["Invoice_Statement.pdf.exe"]


def test_safe_attachment_extension_not_flagged():
    email = _blank_email(
        attachments=[Attachment(filename="report.pdf", content_type="application/pdf", size=100)]
    )
    assert check_attachments(email) == []


def test_missing_auth_results_flagged_as_low_severity():
    email = _blank_email(authentication_results_raw=None)
    findings = check_authentication(email)
    assert len(findings) == 1
    assert findings[0].type == "auth_results_missing"


def test_passing_auth_results_produce_no_findings():
    email = _blank_email(
        authentication_results_raw="mx; spf=pass smtp.mailfrom=acme.com; dkim=pass; dmarc=pass"
    )
    assert check_authentication(email) == []
