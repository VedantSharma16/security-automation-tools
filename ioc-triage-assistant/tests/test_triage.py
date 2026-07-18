import pytest

from ioc_triage.knowledge_base import TechniqueKnowledgeBase
from ioc_triage.llm_client import LLMClient
from ioc_triage.triage import SEVERITY_LOW, run_triage, score_severity


@pytest.fixture(scope="module")
def kb():
    return TechniqueKnowledgeBase.from_file()


def test_run_triage_end_to_end_flags_known_malicious_ip(kb):
    alert = (
        "Outbound beacon from workstation to 185.220.101.1 every 5 minutes, "
        "encoded powershell command line observed, ransomware note dropped, files encrypted."
    )
    report = run_triage(alert, knowledge_base=kb, llm_client=LLMClient(api_key=None))

    ioc_values = {i.value for i in report.indicators}
    assert "185.220.101.1" in ioc_values

    flagged = [e for e in report.enrichment if e.is_known_malicious]
    assert any(e.value == "185.220.101.1" for e in flagged)

    assert report.severity in {"critical", "high"}
    assert report.llm_backed is False
    assert "185.220.101.1" in report.summary or "offline heuristic summary" in report.summary


def test_run_triage_benign_alert_is_low_severity(kb):
    alert = "User successfully logged in from their usual office IP 10.0.0.5 at 09:00."
    report = run_triage(alert, knowledge_base=kb, llm_client=LLMClient(api_key=None))
    assert report.severity == SEVERITY_LOW


def test_score_severity_critical_requires_high_confidence_and_impact_tactic():
    from ioc_triage.enrichment import EnrichmentResult
    from ioc_triage.knowledge_base import Technique

    enrichment = [
        EnrichmentResult(
            value="x", category="ipv4", is_known_malicious=True,
            confidence="high", source="demo-feed", notes="",
        )
    ]
    matched = [(Technique(id="T1486", name="Data Encrypted for Impact", tactic="Impact", text="..."), 0.5)]
    assert score_severity(enrichment, matched) == "critical"


def test_score_severity_low_with_no_signal():
    assert score_severity([], []) == "low"


def test_report_to_dict_is_json_serializable(kb):
    import json

    report = run_triage("Nothing suspicious here.", knowledge_base=kb, llm_client=LLMClient(api_key=None))
    serialized = json.dumps(report.to_dict())
    assert "severity" in serialized
