from pathlib import Path

from soc_agent.router import HeuristicRouter, LLMRouter

FIXTURES = Path(__file__).parent / "fixtures"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_auth_log_evidence_routes_to_log_triage_only():
    decision = HeuristicRouter().route(_read("auth_evidence.txt"))
    assert decision.run_log_triage is True
    assert decision.run_ioc_triage is False
    assert decision.mode == "heuristic"
    assert decision.reasoning  # explains itself


def test_alert_evidence_routes_to_ioc_triage_only():
    decision = HeuristicRouter().route(_read("alert_evidence.txt"))
    assert decision.run_log_triage is False
    assert decision.run_ioc_triage is True


def test_mixed_evidence_routes_to_both():
    decision = HeuristicRouter().route(_read("mixed_evidence.txt"))
    assert decision.run_log_triage is True
    assert decision.run_ioc_triage is True


def test_benign_evidence_falls_back_to_ioc_triage():
    decision = HeuristicRouter().route(_read("benign_evidence.txt"))
    assert decision.run_log_triage is False
    assert decision.run_ioc_triage is True
    assert "fallback" in decision.reasoning[0]


def test_llm_router_without_api_key_falls_back_to_heuristic(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    router = LLMRouter()
    assert router.is_live is False

    decision = router.route(_read("auth_evidence.txt"))
    assert decision.run_log_triage is True
    assert decision.run_ioc_triage is False
    assert "heuristic" in decision.reasoning[0]


def test_llm_router_uses_tool_call_result_when_live(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    class FakeToolUseBlock:
        type = "tool_use"
        input = {
            "run_log_triage": False,
            "run_ioc_triage": True,
            "reasoning": "Evidence is alert text with indicators of compromise.",
        }

    class FakeResponse:
        content = [FakeToolUseBlock()]

    class FakeMessages:
        def create(self, **kwargs):
            assert kwargs["tools"][0]["name"] == "route_evidence"
            return FakeResponse()

    class FakeClient:
        def __init__(self, api_key=None):
            self.messages = FakeMessages()

    import sys

    fake_anthropic_module = type("module", (), {"Anthropic": FakeClient})
    monkeypatch.setitem(sys.modules, "anthropic", fake_anthropic_module)

    router = LLMRouter()
    assert router.is_live is True

    decision = router.route("some alert text")
    assert decision.mode == "llm"
    assert decision.run_log_triage is False
    assert decision.run_ioc_triage is True
    assert "indicators of compromise" in decision.reasoning[0]
