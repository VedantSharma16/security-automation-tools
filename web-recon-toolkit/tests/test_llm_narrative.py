from webrecon.llm_narrative import TemplateSummarizer, get_summarizer
from webrecon.pipeline import analyze


def test_get_summarizer_defaults_to_template_without_llm_flag():
    assert isinstance(get_summarizer(use_llm=False), TemplateSummarizer)


def test_get_summarizer_falls_back_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_summarizer(use_llm=True), TemplateSummarizer)


def test_template_summarizer_reports_unreachable_target():
    result = analyze({"url": "https://down.test", "status_code": 0, "headers": {}, "body": "", "error": "timed out"})
    narrative = TemplateSummarizer().summarize(result)
    assert "could not be reached" in narrative
    assert "timed out" in narrative


def test_template_summarizer_surfaces_findings_and_technologies():
    result = analyze({
        "url": "https://example.test",
        "status_code": 200,
        "headers": {"Server": "nginx"},
        "body": "<div class='wp-content'></div>",
    })
    narrative = TemplateSummarizer().summarize(result)
    assert "Security header grade" in narrative
    assert "content-security-policy" in narrative.lower()
    assert "nginx" in narrative.lower() or "WordPress" in narrative


def test_template_summarizer_reports_clean_result():
    result = analyze({
        "url": "https://example.test",
        "status_code": 200,
        "headers": {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Permissions-Policy": "geolocation=()",
            "Referrer-Policy": "no-referrer",
        },
        "body": "",
    })
    narrative = TemplateSummarizer().summarize(result)
    assert "No missing security headers" in narrative
