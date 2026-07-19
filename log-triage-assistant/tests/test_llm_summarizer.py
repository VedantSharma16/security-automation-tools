from pathlib import Path

from logtriage.detectors import run_all_detectors
from logtriage.llm_summarizer import TemplateSummarizer, get_summarizer
from logtriage.parser import parse_file
from logtriage.report import build_report

FIXTURES = Path(__file__).parent / "fixtures"


def test_get_summarizer_defaults_to_template_without_llm_flag():
    assert isinstance(get_summarizer(use_llm=False), TemplateSummarizer)


def test_get_summarizer_falls_back_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_summarizer(use_llm=True), TemplateSummarizer)


def test_template_summarizer_reports_no_findings_message():
    events = parse_file(FIXTURES / "sample_auth_clean.log", default_year=2026)
    report = build_report(FIXTURES / "sample_auth_clean.log", events, [])
    narrative = TemplateSummarizer().summarize(report)
    assert "No security-relevant patterns" in narrative


def test_template_summarizer_mentions_each_finding_category():
    events = parse_file(FIXTURES / "sample_auth.log", default_year=2026)
    findings = run_all_detectors(events)
    report = build_report(FIXTURES / "sample_auth.log", events, findings)
    narrative = TemplateSummarizer().summarize(report)

    assert "brute-force" in narrative.lower()
    assert "privilege escalation" in narrative.lower()
    assert "persistence" in narrative.lower()
