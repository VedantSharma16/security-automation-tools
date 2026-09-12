from webrecon.findings import Finding
from webrecon.llm_summarizer import LLMSummarizer, build_prompt
from webrecon.scoring import assess_risk


def _finding(severity="high", fid="missing-hsts"):
    return Finding(
        id=fid, category="headers", severity=severity, title=fid, detail="d", recommendation="r"
    )


def test_no_api_key_is_not_live(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    summarizer = LLMSummarizer(api_key=None)
    assert summarizer.is_live is False


def test_offline_summary_mentions_overall_risk_and_top_finding(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    findings = [_finding("high"), _finding("low", "missing-nosniff")]
    risk = assess_risk(findings)
    summarizer = LLMSummarizer(api_key=None)

    summary = summarizer.summarize("http://example.com", findings, risk)

    assert "offline heuristic summary" in summary
    assert risk.overall_severity.upper() in summary
    assert "missing-hsts" in summary  # the worst finding, named explicitly


def test_offline_summary_handles_no_findings(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    risk = assess_risk([])
    summarizer = LLMSummarizer(api_key=None)

    summary = summarizer.summarize("http://example.com", [], risk)

    assert "No findings were raised" in summary


def test_build_prompt_includes_target_and_findings():
    findings = [_finding("critical")]
    risk = assess_risk(findings)
    prompt = build_prompt("http://example.com", findings, risk)
    assert "http://example.com" in prompt
    assert "CRITICAL" in prompt
    assert "missing-hsts" in prompt
