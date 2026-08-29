from asm.findings import Finding, Severity
from asm.llm_summarizer import TemplateSummarizer, get_summarizer
from asm.report import build_report


def _report(findings):
    return build_report(
        domain="example.com",
        dns_records={},
        subdomains=[],
        http_result={"https": None, "http": None},
        tls_info=None,
        findings=findings,
    )


def test_get_summarizer_defaults_to_template_without_llm_flag():
    assert isinstance(get_summarizer(use_llm=False), TemplateSummarizer)


def test_get_summarizer_falls_back_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_summarizer(use_llm=True), TemplateSummarizer)


def test_template_summarizer_reports_no_findings_message():
    report = _report([])
    narrative = TemplateSummarizer().summarize(report)
    assert "No actionable security findings" in narrative


def test_template_summarizer_ignores_info_only_findings():
    report = _report([Finding("dns", Severity.INFO, "A records resolved", "1.2.3.4")])
    narrative = TemplateSummarizer().summarize(report)
    assert "No actionable security findings" in narrative


def test_template_summarizer_mentions_each_source_category():
    findings = [
        Finding("tls", Severity.HIGH, "cert expiring", "..."),
        Finding("http_headers", Severity.MEDIUM, "missing CSP", "..."),
        Finding("dns", Severity.MEDIUM, "no SPF", "..."),
        Finding("subdomains", Severity.LOW, "large surface", "..."),
    ]
    narrative = TemplateSummarizer().summarize(_report(findings))
    assert "TLS/certificate" in narrative
    assert "HTTP security header" in narrative
    assert "DNS/email-security" in narrative
    assert "subdomain-exposure" in narrative
