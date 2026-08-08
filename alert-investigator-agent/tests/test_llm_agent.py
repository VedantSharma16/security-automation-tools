import pytest

from investigator.llm_agent import AgentIncompleteError, LLMAgent
from investigator.state import Alert


class FakeBlock:
    def __init__(self, type_, **kwargs):
        self.type = type_
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeResponse:
    def __init__(self, content):
        self.content = content


class FakeMessages:
    def __init__(self, responses):
        self._responses = iter(responses)

    def create(self, **kwargs):
        return next(self._responses)


class FakeClient:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


def _alert():
    return Alert(alert_id="A1", description="Suspicious login burst.", indicators=["185.220.101.45"], host="fin-db-03")


def test_full_loop_gathers_evidence_then_submits_verdict():
    responses = [
        FakeResponse(
            [
                FakeBlock("text", text="Checking reputation of the indicator first."),
                FakeBlock(
                    "tool_use",
                    id="t1",
                    name="lookup_indicator_reputation",
                    input={"indicator": "185.220.101.45"},
                ),
            ]
        ),
        FakeResponse(
            [
                FakeBlock(
                    "tool_use",
                    id="t2",
                    name="calculate_risk_score",
                    input={"signals": {"any_known_malicious": True, "max_confidence": "high"}},
                )
            ]
        ),
        FakeResponse(
            [
                FakeBlock(
                    "tool_use",
                    id="t3",
                    name="submit_verdict",
                    input={
                        "verdict": "true_positive",
                        "confidence": "high",
                        "risk_score": 90,
                        "risk_band": "critical",
                        "summary": "Malicious indicator confirmed against known-bad infrastructure.",
                        "recommended_actions": ["Isolate host", "Escalate to IR"],
                    },
                )
            ]
        ),
    ]
    agent = LLMAgent(client=FakeClient(responses))

    result = agent.investigate(_alert())

    assert result.mode == "llm_agent"
    assert result.verdict == "true_positive"
    assert result.risk_score == 90
    assert len(result.trace) == 2
    assert result.trace[0].tool == "lookup_indicator_reputation"
    assert result.trace[0].reasoning == "Checking reputation of the indicator first."
    assert result.trace[1].tool == "calculate_risk_score"


def test_loop_raises_when_iteration_budget_exhausted():
    responses = [
        FakeResponse(
            [FakeBlock("tool_use", id=f"t{i}", name="lookup_indicator_reputation", input={"indicator": "8.8.8.8"})]
        )
        for i in range(2)
    ]
    agent = LLMAgent(client=FakeClient(responses), max_iterations=2)

    with pytest.raises(AgentIncompleteError):
        agent.investigate(_alert())


def test_loop_raises_when_model_stops_without_submitting_verdict():
    responses = [FakeResponse([FakeBlock("text", text="I'm not confident enough to conclude.")])]
    agent = LLMAgent(client=FakeClient(responses), max_iterations=5)

    with pytest.raises(AgentIncompleteError):
        agent.investigate(_alert())


def test_agent_not_live_without_api_key_or_client(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    agent = LLMAgent()
    assert agent.is_live is False


def test_investigate_raises_runtime_error_when_not_live(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    agent = LLMAgent()
    with pytest.raises(RuntimeError):
        agent.investigate(_alert())


def test_client_injection_marks_agent_live():
    agent = LLMAgent(client=FakeClient([]))
    assert agent.is_live is True
