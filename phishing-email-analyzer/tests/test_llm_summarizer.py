from phishtriage.llm_summarizer import TemplateSummarizer, get_summarizer


def test_template_summarizer_handles_no_findings():
    report = {"summary": {"total_findings": 0}, "findings": []}
    text = TemplateSummarizer().summarize(report)
    assert "No phishing indicators" in text


def test_template_summarizer_mentions_key_finding_types():
    report = {
        "summary": {"total_findings": 2, "highest_severity": "CRITICAL", "risk_score": 90, "verdict": "likely_phishing"},
        "findings": [
            {"type": "auth_failure"},
            {"type": "dangerous_attachment"},
        ],
    }
    text = TemplateSummarizer().summarize(report)
    assert "authentication" in text.lower()
    assert "attachment" in text.lower()


def test_get_summarizer_without_llm_flag_returns_template():
    assert isinstance(get_summarizer(False), TemplateSummarizer)


def test_get_summarizer_falls_back_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_summarizer(True), TemplateSummarizer)
