"""Tests for the LLM tool-use loop, using a fake Anthropic client.

The real ``anthropic`` package is an optional dependency and isn't required
to exercise the loop's control flow: we inject a fake client directly onto
``LLMAgent._client`` (bypassing the constructor's real SDK import) so the
step-by-step tool-execution, message-threading, and finish-parsing logic is
covered without any network access or the SDK installed.
"""

from ir_agent.llm_agent import LLMAgent


class FakeBlock:
    def __init__(self, type, **kwargs):
        self.type = type
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeResponse:
    def __init__(self, content):
        self.content = content


class FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        # Snapshot the messages list: the caller keeps mutating the same list
        # object after this call returns, so a bare reference would show
        # later state instead of what was actually sent on this call.
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})
        return self._responses.pop(0)


class FakeClient:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


def _agent_with_fake_client(responses) -> LLMAgent:
    agent = LLMAgent(api_key=None)  # real SDK import skipped, self._client stays None
    agent._client = FakeClient(responses)
    return agent


def test_is_live_false_without_client():
    agent = LLMAgent(api_key=None)
    assert agent.is_live is False


def test_immediate_finish_call_is_parsed_directly():
    finish_block = FakeBlock(
        "tool_use",
        id="toolu_1",
        name="finish",
        input={"severity": "high", "confidence": 0.8, "summary": "Confirmed C2 beacon.", "recommended_actions": ["Isolate host"]},
    )
    agent = _agent_with_fake_client([FakeResponse([finish_block])])

    verdict = agent.run("some incident text", max_steps=4)

    assert verdict.severity == "high"
    assert verdict.confidence == 0.8
    assert verdict.recommended_actions == ["Isolate host"]
    assert verdict.llm_backed is True
    assert verdict.evidence == []
    assert len(agent._client.messages.calls) == 1


def test_multi_step_loop_executes_tool_then_finishes():
    step1 = FakeResponse(
        [
            FakeBlock("text", text="Checking the IP first."),
            FakeBlock("tool_use", id="toolu_1", name="check_ip_reputation", input={"ip": "185.220.101.1"}),
        ]
    )
    step2 = FakeResponse(
        [
            FakeBlock(
                "tool_use",
                id="toolu_2",
                name="finish",
                input={
                    "severity": "critical",
                    "confidence": 0.9,
                    "summary": "Known-malicious Tor exit node confirmed.",
                    "recommended_actions": ["Block the IP"],
                },
            )
        ]
    )
    agent = _agent_with_fake_client([step1, step2])

    verdict = agent.run("beacon to 185.220.101.1", max_steps=4)

    assert verdict.severity == "critical"
    assert len(verdict.evidence) == 1
    assert verdict.evidence[0].tool == "check_ip_reputation"
    assert verdict.evidence[0].malicious is True
    assert len(agent._client.messages.calls) == 2
    # the second call's messages must include the tool_result from step 1
    second_call_messages = agent._client.messages.calls[1]["messages"]
    assert second_call_messages[-1]["content"][0]["type"] == "tool_result"


def test_loop_synthesizes_verdict_if_finish_never_called():
    tool_step = FakeResponse(
        [FakeBlock("tool_use", id="toolu_1", name="check_ip_reputation", input={"ip": "8.8.8.8"})]
    )
    agent = _agent_with_fake_client([tool_step, tool_step])  # never calls finish, exhausts max_steps

    verdict = agent.run("mentions 8.8.8.8 twice", max_steps=2)

    assert verdict.llm_backed is True
    assert "did not call finish" in verdict.summary
    assert len(verdict.evidence) == 2
