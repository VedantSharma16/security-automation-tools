from agentic_soc.agent import SocAgent
from agentic_soc.tools import ToolRegistry
from tests.fakes import FakeClient, FakeResponse, FakeToolUseBlock


def test_soc_agent_uses_offline_planner_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    agent = SocAgent(api_key=None)
    assert agent.is_live is False

    transcript = agent.investigate("Routine login from a known corporate IP.")
    assert transcript.llm_backed is False


def test_soc_agent_falls_back_to_offline_when_live_agent_errors(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    registry = ToolRegistry.from_files()
    agent = SocAgent(registry=registry, api_key=None)

    class ExplodingClient:
        class messages:
            @staticmethod
            def create(**kwargs):
                raise RuntimeError("simulated network failure")

    agent._llm_agent._client = ExplodingClient()

    transcript = agent.investigate("some alert")
    assert transcript.llm_backed is False
    assert "offline deterministic planner used instead" in transcript.verdict.reasoning


def test_soc_agent_uses_live_agent_when_client_present():
    registry = ToolRegistry.from_files()
    client = FakeClient(
        [
            FakeResponse(
                [
                    FakeToolUseBlock(
                        "submit_verdict",
                        {"verdict": "benign", "confidence": 0.6, "reasoning": "Nothing notable.", "recommended_actions": []},
                        id="t1",
                    )
                ]
            )
        ]
    )
    agent = SocAgent(registry=registry)
    agent._llm_agent._client = client

    transcript = agent.investigate("some alert")
    assert transcript.llm_backed is True
    assert transcript.verdict.verdict == "benign"
