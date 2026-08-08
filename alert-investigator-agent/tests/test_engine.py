from investigator import engine
from investigator.llm_agent import AgentIncompleteError, LLMAgent
from investigator.state import Alert, InvestigationResult


def _alert():
    return Alert(alert_id="ALT-100", description="Test alert.", indicators=["8.8.8.8"], host="web-app-12")


def test_investigate_uses_offline_planner_when_no_llm_configured(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = engine.investigate(_alert())
    assert result.mode == "offline_planner"


def test_investigate_respects_use_llm_false():
    fake_agent = LLMAgent(client=object())  # is_live True, but use_llm=False should skip it entirely
    result = engine.investigate(_alert(), use_llm=False, agent=fake_agent)
    assert result.mode == "offline_planner"


class _StubSucceedingAgent:
    is_live = True

    def investigate(self, alert):
        return InvestigationResult(
            alert=alert,
            trace=[],
            risk_score=90,
            risk_band="critical",
            verdict="true_positive",
            confidence="high",
            summary="stub summary",
            recommended_actions=["stub action"],
            mode="llm_agent",
        )


class _StubFailingAgent:
    is_live = True

    def investigate(self, alert):
        raise AgentIncompleteError("never converged")


def test_investigate_uses_live_agent_result_when_it_succeeds():
    result = engine.investigate(_alert(), agent=_StubSucceedingAgent())
    assert result.mode == "llm_agent"
    assert result.verdict == "true_positive"


def test_investigate_falls_back_to_planner_when_live_agent_fails():
    result = engine.investigate(_alert(), agent=_StubFailingAgent())
    assert result.mode == "offline_planner"
    assert "LLM agent unavailable" in result.summary
