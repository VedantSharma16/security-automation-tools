from pathlib import Path

from phishtriage.detectors import run_all_detectors
from phishtriage.llm_summarizer import TemplateSummarizer, get_summarizer
from phishtriage.parser import parse_file
from phishtriage.report import build_report

FIXTURES = Path(__file__).parent / "fixtures"


def test_get_summarizer_defaults_to_template_without_llm_flag():
    assert isinstance(get_summarizer(use_llm=False), TemplateSummarizer)


def test_get_summarizer_falls_back_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_summarizer(use_llm=True), TemplateSummarizer)


def test_template_summarizer_reports_no_findings_message():
    msg = parse_file(FIXTURES / "benign_newsletter.eml")
    report = build_report(msg, [])
    narrative = TemplateSummarizer().summarize(report)
    assert "No phishing indicators were detected" in narrative


def test_template_summarizer_mentions_each_finding_category():
    msg = parse_file(FIXTURES / "phishing_paypal.eml")
    findings = run_all_detectors(msg)
    report = build_report(msg, findings)
    narrative = TemplateSummarizer().summarize(report)

    assert "spoofed" in narrative.lower()
    assert "attachment" in narrative.lower()
    assert "impersonation" in narrative.lower()
    assert "urgency" in narrative.lower()
