from soc_agent.aggregator import build_report
from soc_agent.narrative import TemplateNarrator, get_narrator
from soc_agent.router import RouterDecision
from soc_agent.tools import ToolResult, skipped


def test_template_narrator_reports_clean_result():
    report = build_report(
        {"log_triage": skipped("log_triage", "n/a"), "ioc_triage": skipped("ioc_triage", "n/a")},
        router_decision=None,
        evidence_source="clean.txt",
    )
    narrative = TemplateNarrator().narrate(report)
    assert "No security-relevant findings" in narrative


def test_template_narrator_mentions_severity_and_actions():
    raw = {"enrichment": [{"value": "1.2.3.4", "is_known_malicious": True, "confidence": "high"}]}
    result = ToolResult(
        tool="ioc_triage", status="ok", severity="critical", finding_count=1, headline="1 finding(s)", raw=raw
    )
    decision = RouterDecision(run_log_triage=False, run_ioc_triage=True, reasoning=["alert text detected"])
    report = build_report({"ioc_triage": result}, decision, evidence_source="alert.txt")

    narrative = TemplateNarrator().narrate(report)
    assert "CRITICAL" in narrative
    assert "1.2.3.4" in narrative


def test_get_narrator_defaults_to_template_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    narrator = get_narrator(use_llm=True)
    assert isinstance(narrator, TemplateNarrator)


def test_get_narrator_without_llm_flag_is_template():
    narrator = get_narrator(use_llm=False)
    assert isinstance(narrator, TemplateNarrator)
