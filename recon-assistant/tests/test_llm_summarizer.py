from recon_assistant.llm_summarizer import TemplateSummarizer, get_summarizer


def report_with(findings, open_port_count=1):
    return {
        "target": "10.0.0.5",
        "summary": {
            "open_port_count": open_port_count,
            "total_findings": len(findings),
            "highest_severity": "high" if findings else "none",
            "risk_score": 20 if findings else 0,
        },
        "findings": findings,
    }


def test_template_summarizer_no_findings():
    summary = TemplateSummarizer().summarize(report_with([]))
    assert "no risk findings" in summary


def test_template_summarizer_mentions_exposed_database():
    findings = [{"type": "exposed_database", "port": 6379, "severity": "high"}]
    summary = TemplateSummarizer().summarize(report_with(findings))
    assert "Database service(s)" in summary
    assert "port 6379" in summary


def test_get_summarizer_defaults_to_template_without_llm_flag():
    assert isinstance(get_summarizer(use_llm=False), TemplateSummarizer)


def test_get_summarizer_falls_back_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_summarizer(use_llm=True), TemplateSummarizer)
