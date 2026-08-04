from __future__ import annotations

import os

from phishing_triage.auth_analysis import analyze_authentication
from phishing_triage.content_analysis import analyze_attachments, analyze_content, analyze_sender
from phishing_triage.llm_summarizer import TemplateSummarizer, get_summarizer
from phishing_triage.parser import parse_file
from phishing_triage.report import build_report
from phishing_triage.scoring import score_email
from phishing_triage.url_analysis import analyze_links

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHISHING_SAMPLE = os.path.join(PROJECT_ROOT, "examples", "phishing_sample.eml")
LEGIT_SAMPLE = os.path.join(PROJECT_ROOT, "examples", "legitimate_sample.eml")


def _report_for(path: str) -> dict:
    parsed = parse_file(path)
    auth = analyze_authentication(parsed.authentication_results_raw)
    url_findings = analyze_links(parsed.links)
    content = analyze_content(parsed.subject, parsed.visible_text)
    sender = analyze_sender(parsed.from_display, parsed.from_domain)
    attachment_findings = analyze_attachments(parsed.attachments)
    triage = score_email(auth, url_findings, content, sender, attachment_findings)
    return build_report(parsed, auth, url_findings, content, sender, attachment_findings, triage)


def test_get_summarizer_defaults_to_template_without_llm_flag():
    assert isinstance(get_summarizer(use_llm=False), TemplateSummarizer)


def test_get_summarizer_falls_back_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_summarizer(use_llm=True), TemplateSummarizer)


def test_template_summarizer_reports_no_indicators_for_clean_email():
    report = _report_for(LEGIT_SAMPLE)
    narrative = TemplateSummarizer().summarize(report)
    assert "No phishing indicators" in narrative


def test_template_summarizer_states_verdict_and_key_indicators():
    report = _report_for(PHISHING_SAMPLE)
    narrative = TemplateSummarizer().summarize(report)
    assert "LIKELY PHISHING" in narrative
    assert "Key indicators:" in narrative
    assert "do not click any links" in narrative.lower()
