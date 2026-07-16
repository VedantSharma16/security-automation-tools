from log_sentinel.knowledge_base import KnowledgeBase
from log_sentinel.models import Alert, Severity
from log_sentinel.triage import AlertTriageEngine


class StubLLMClient:
    def __init__(self):
        self.last_system = None
        self.last_prompt = None

    def complete(self, system, prompt):
        self.last_system = system
        self.last_prompt = prompt
        return "stubbed triage response"


def make_alert():
    return Alert(
        rule_id="SSH-001",
        title="SSH brute-force attempt",
        severity=Severity.HIGH,
        description="5 failed password attempts from 203.0.113.7 within 5 minutes.",
        events=[],
        tags=["brute-force", "password", "ssh"],
    )


def test_triage_uses_llm_client_when_provided():
    stub = StubLLMClient()
    engine = AlertTriageEngine(KnowledgeBase.load(), llm_client=stub)
    result = engine.triage(make_alert())
    assert result == "stubbed triage response"
    assert "T1110" in stub.last_prompt


def test_triage_falls_back_to_heuristic_without_llm_client():
    engine = AlertTriageEngine(KnowledgeBase.load(), llm_client=None)
    result = engine.triage(make_alert())
    assert "offline triage" in result
    assert "SSH brute-force attempt" in result


def test_build_prompt_includes_attck_context():
    engine = AlertTriageEngine(KnowledgeBase.load())
    system, prompt = engine.build_prompt(make_alert())
    assert "ATT&CK" in system
    assert "T1110" in prompt
