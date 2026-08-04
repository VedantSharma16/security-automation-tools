from __future__ import annotations

from phishing_triage.content_analysis import (
    analyze_attachments,
    analyze_content,
    analyze_sender,
)
from phishing_triage.parser import Attachment


def test_benign_content_has_no_matches():
    findings = analyze_content("Team lunch on Friday", "See you all at noon in the kitchen.")
    assert findings.matched_urgency_phrases == ()
    assert findings.matched_sensitive_info_keywords == ()
    assert findings.matched_generic_greeting is None
    assert findings.weight == 0


def test_urgency_phrases_detected_and_weighted():
    findings = analyze_content(
        "Urgent Action Required",
        "Your account will be suspended within 24 hours. Act now.",
    )
    assert "urgent action required" in findings.matched_urgency_phrases
    assert "within 24 hours" in findings.matched_urgency_phrases
    assert findings.weight > 0


def test_urgency_weight_is_capped():
    many_phrases = " ".join(
        [
            "act now", "act immediately", "urgent action required",
            "unusual activity", "final notice", "expires today",
        ]
    )
    findings = analyze_content("", many_phrases)
    assert findings.weight <= 24 + 5  # urgency cap + no sensitive/greeting hits


def test_sensitive_info_keyword_detected():
    findings = analyze_content("", "Please confirm your password to continue.")
    assert "confirm your password" in findings.matched_sensitive_info_keywords
    assert findings.weight >= 15


def test_generic_greeting_detected():
    findings = analyze_content("", "Dear Customer, please review your statement.")
    assert findings.matched_generic_greeting == "dear customer"


def test_sender_impersonation_flagged_when_domain_mismatches_brand():
    finding = analyze_sender("PayPal Security Team", "paypa1-support.tk")
    assert finding.claimed_brand == "paypal"
    assert finding.is_impersonation is True
    assert finding.weight == 25


def test_sender_not_flagged_when_domain_matches_brand():
    finding = analyze_sender("PayPal", "paypal.com")
    assert finding.claimed_brand == "paypal"
    assert finding.is_impersonation is False
    assert finding.weight == 0


def test_sender_not_flagged_when_no_brand_claimed():
    finding = analyze_sender("Alice from Accounting", "recipient-corp.example")
    assert finding.claimed_brand is None
    assert finding.is_impersonation is False


def test_double_extension_attachment_flagged():
    findings = analyze_attachments(
        (Attachment(filename="invoice.pdf.exe", content_type="application/octet-stream", size_bytes=10),)
    )
    assert len(findings) == 1
    assert findings[0].is_double_extension is True
    assert findings[0].weight == 35


def test_dangerous_extension_without_double_extension_flagged():
    findings = analyze_attachments(
        (Attachment(filename="payload.exe", content_type="application/octet-stream", size_bytes=10),)
    )
    assert findings[0].is_dangerous_extension is True
    assert findings[0].is_double_extension is False
    assert findings[0].weight == 30


def test_safe_attachment_not_flagged():
    findings = analyze_attachments(
        (Attachment(filename="quarterly_report.pdf", content_type="application/pdf", size_bytes=1024),)
    )
    assert findings[0].is_dangerous_extension is False
    assert findings[0].is_double_extension is False
    assert findings[0].weight == 0


def test_no_attachments_returns_empty_list():
    assert analyze_attachments(()) == []
