from __future__ import annotations

from phishing_triage.auth_analysis import AuthResult
from phishing_triage.content_analysis import AttachmentFinding, ContentFindings, SenderFinding
from phishing_triage.scoring import Verdict, score_email
from phishing_triage.url_analysis import UrlFinding

CLEAN_AUTH = AuthResult(header_present=True, spf="pass", dkim="pass", dmarc="pass")
EMPTY_CONTENT = ContentFindings()
EMPTY_SENDER = SenderFinding(from_display="Alice", from_domain="example.com")


def test_clean_email_scores_zero_and_benign():
    result = score_email(CLEAN_AUTH, [], EMPTY_CONTENT, EMPTY_SENDER, [])
    assert result.score == 0
    assert result.verdict == Verdict.BENIGN
    assert result.reasons == ()


def test_missing_auth_header_adds_small_penalty_only():
    result = score_email(
        AuthResult(header_present=False, spf=None, dkim=None, dmarc=None),
        [], EMPTY_CONTENT, EMPTY_SENDER, [],
    )
    assert result.score == 5
    assert result.verdict == Verdict.BENIGN


def test_auth_hard_fails_push_toward_suspicious():
    auth = AuthResult(header_present=True, spf="fail", dkim="fail", dmarc="fail")
    result = score_email(auth, [], EMPTY_CONTENT, EMPTY_SENDER, [])
    assert result.score == 45
    assert result.verdict == Verdict.SUSPICIOUS


def test_url_findings_contribute_and_are_capped():
    heavy_findings = [
        UrlFinding(href="http://x", display_text="x", host="x", weight=40, reasons=("a",)),
        UrlFinding(href="http://y", display_text="y", host="y", weight=40, reasons=("b",)),
    ]
    result = score_email(CLEAN_AUTH, heavy_findings, EMPTY_CONTENT, EMPTY_SENDER, [])
    assert result.score == 50  # capped at MAX_URL_CONTRIBUTION, not 80
    assert "a" in result.reasons
    assert "b" in result.reasons


def test_attachment_findings_contribute_and_are_capped():
    heavy_attachments = [
        AttachmentFinding(filename="a.exe", content_type="x", weight=35, reasons=("bad a",)),
        AttachmentFinding(filename="b.exe", content_type="x", weight=35, reasons=("bad b",)),
    ]
    result = score_email(CLEAN_AUTH, [], EMPTY_CONTENT, EMPTY_SENDER, heavy_attachments)
    assert result.score == 40  # capped at MAX_ATTACHMENT_CONTRIBUTION, not 70


def test_score_never_exceeds_100():
    auth = AuthResult(header_present=True, spf="fail", dkim="fail", dmarc="fail")
    content = ContentFindings(weight=100)
    sender = SenderFinding(
        from_display="Bank", from_domain="evil.tk", claimed_brand="chase",
        is_impersonation=True, weight=25,
    )
    result = score_email(auth, [], content, sender, [])
    assert result.score == 100
    assert result.verdict == Verdict.LIKELY_PHISHING


def test_verdict_thresholds():
    # Just under the suspicious threshold.
    content = ContentFindings(weight=24)
    result = score_email(CLEAN_AUTH, [], content, EMPTY_SENDER, [])
    assert result.score == 24
    assert result.verdict == Verdict.BENIGN

    content = ContentFindings(weight=25)
    result = score_email(CLEAN_AUTH, [], content, EMPTY_SENDER, [])
    assert result.verdict == Verdict.SUSPICIOUS

    content = ContentFindings(weight=60)
    result = score_email(CLEAN_AUTH, [], content, EMPTY_SENDER, [])
    assert result.verdict == Verdict.LIKELY_PHISHING
