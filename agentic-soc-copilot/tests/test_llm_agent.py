from agentic_soc.llm_agent import LLMAgent
from agentic_soc.tools import ToolRegistry
from tests.fakes import FakeClient, FakeResponse, FakeTextBlock, FakeToolUseBlock


def test_llm_agent_without_client_or_key_is_not_live(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    agent = LLMAgent(ToolRegistry.from_files(), api_key=None)
    assert agent.is_live is False


def test_llm_agent_runs_tool_then_submits_verdict():
    registry = ToolRegistry.from_files()
    responses = [
        FakeResponse(
            [
                FakeTextBlock("Checking the IP against threat intel."),
                FakeToolUseBlock("lookup_ioc", {"indicator": "91.203.145.12"}, id="t1"),
            ]
        ),
        FakeResponse(
            [
                FakeTextBlock("This IP is a known bad actor; concluding."),
                FakeToolUseBlock(
                    "submit_verdict",
                    {
                        "verdict": "malicious",
                        "confidence": 0.9,
                        "reasoning": "Matched a known-malicious IP in threat intel.",
                        "recommended_actions": ["Isolate the host."],
                    },
                    id="t2",
                ),
            ]
        ),
    ]
    client = FakeClient(responses)
    agent = LLMAgent(registry, client=client)
    assert agent.is_live is True

    transcript = agent.investigate("Alert mentioning 91.203.145.12")

    assert transcript.llm_backed is True
    assert transcript.steps_used == 1
    assert transcript.steps[0].tool == "lookup_ioc"
    assert transcript.steps[0].observation["matched"] is True
    assert transcript.steps[0].thought == "Checking the IP against threat intel."
    assert transcript.verdict.verdict == "malicious"
    assert transcript.verdict.confidence == 0.9
    assert len(client.messages.calls) == 2


def test_llm_agent_handles_multiple_tool_calls_in_one_turn():
    registry = ToolRegistry.from_files()
    responses = [
        FakeResponse(
            [
                FakeToolUseBlock("lookup_ioc", {"indicator": "91.203.145.12"}, id="t1"),
                FakeToolUseBlock("check_process", {"process_name": "powershell.exe"}, id="t2"),
            ]
        ),
        FakeResponse(
            [
                FakeToolUseBlock(
                    "submit_verdict",
                    {
                        "verdict": "malicious",
                        "confidence": 0.85,
                        "reasoning": "Known-malicious IP plus a high-risk LOLBin.",
                        "recommended_actions": ["Isolate the host."],
                    },
                    id="t3",
                )
            ]
        ),
    ]
    agent = LLMAgent(registry, client=FakeClient(responses))
    transcript = agent.investigate("some alert")

    assert transcript.steps_used == 2
    assert {s.tool for s in transcript.steps} == {"lookup_ioc", "check_process"}


def test_llm_agent_reports_unknown_tool_gracefully():
    registry = ToolRegistry.from_files()
    responses = [
        FakeResponse([FakeToolUseBlock("nonexistent_tool", {"foo": "bar"}, id="t1")]),
        FakeResponse(
            [
                FakeToolUseBlock(
                    "submit_verdict",
                    {"verdict": "benign", "confidence": 0.5, "reasoning": "n/a", "recommended_actions": []},
                    id="t2",
                )
            ]
        ),
    ]
    agent = LLMAgent(registry, client=FakeClient(responses))
    transcript = agent.investigate("some alert")
    assert transcript.steps[0].observation["error"] == "unknown tool nonexistent_tool"


def test_llm_agent_fails_safe_when_step_budget_exhausted():
    registry = ToolRegistry.from_files()
    responses = [
        FakeResponse([FakeToolUseBlock("lookup_ioc", {"indicator": "8.8.8.8"}, id=f"t{i}")]) for i in range(3)
    ]
    agent = LLMAgent(registry, client=FakeClient(responses), max_steps=3)
    transcript = agent.investigate("some alert")

    assert transcript.verdict.verdict == "suspicious"
    assert transcript.verdict.confidence == 0.3
    assert "did not call submit_verdict" in transcript.verdict.reasoning
    assert len(agent._client.messages.calls) == 3


def test_llm_agent_stops_when_model_returns_only_text():
    registry = ToolRegistry.from_files()
    client = FakeClient([FakeResponse([FakeTextBlock("This alert looks routine, no action needed.")])])
    agent = LLMAgent(registry, client=client, max_steps=6)

    transcript = agent.investigate("routine login alert")

    assert transcript.steps_used == 0
    assert transcript.verdict.verdict == "suspicious"
    assert len(client.messages.calls) == 1
