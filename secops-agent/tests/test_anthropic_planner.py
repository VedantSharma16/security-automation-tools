"""Exercises the live tool-use loop's message bookkeeping against a scripted fake
client, so the multi-turn agentic behavior is covered without real network access
or an API key.
"""

from types import SimpleNamespace

import pytest

from secops_agent.agent import SecOpsAgent
from secops_agent.planner import AnthropicPlanner
from secops_agent.tools import ToolRegistry


def _tool_use(call_id, name, arguments):
    return SimpleNamespace(type="tool_use", id=call_id, name=name, input=arguments)


def _text(content):
    return SimpleNamespace(type="text", text=content)


def _response(content, stop_reason):
    return SimpleNamespace(content=content, stop_reason=stop_reason)


class ScriptedClient:
    """Stands in for anthropic.Anthropic: returns queued responses in order."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        # Snapshot messages: the planner keeps mutating the same list object,
        # so without a copy every call in self.calls would alias the final state.
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})
        return self._responses.pop(0)


def test_single_tool_call_then_final_answer():
    client = ScriptedClient(
        [
            _response([_tool_use("call_1", "lookup_ioc", {"indicator": "203.0.113.77"})], "tool_use"),
            _response([_text("Confirmed malicious IP; escalate immediately.")], "end_turn"),
        ]
    )
    planner = AnthropicPlanner(client=client, model="test-model")
    agent = SecOpsAgent(planner=planner, tools=ToolRegistry(), max_iterations=5)

    investigation = agent.investigate("Is 203.0.113.77 malicious?")

    assert [r.tool for r in investigation.trace] == ["lookup_ioc"]
    assert investigation.trace[0].output["is_known_malicious"] is True
    assert investigation.final_report == "Confirmed malicious IP; escalate immediately."
    assert investigation.verdict == "malicious"
    assert investigation.stopped_early is False

    # second API call must carry the tool result back, addressed to the right tool_use_id
    second_call_messages = client.calls[1]["messages"]
    tool_result_message = second_call_messages[-1]
    assert tool_result_message["role"] == "user"
    assert tool_result_message["content"][0]["type"] == "tool_result"
    assert tool_result_message["content"][0]["tool_use_id"] == "call_1"


def test_parallel_tool_calls_are_batched_into_one_tool_result_turn():
    client = ScriptedClient(
        [
            _response(
                [
                    _tool_use("a", "lookup_ioc", {"indicator": "1.2.3.4"}),
                    _tool_use("b", "lookup_ioc", {"indicator": "5.6.7.8"}),
                ],
                "tool_use",
            ),
            _response([_text("Neither indicator is known malicious.")], "end_turn"),
        ]
    )
    planner = AnthropicPlanner(client=client)
    agent = SecOpsAgent(planner=planner, tools=ToolRegistry(), max_iterations=5)

    investigation = agent.investigate("Check both IPs")

    assert len(investigation.trace) == 2
    # both tool calls happen before the second messages.create call
    assert len(client.calls) == 2
    batched_results = client.calls[1]["messages"][-1]["content"]
    assert [r["tool_use_id"] for r in batched_results] == ["a", "b"]


def test_requires_api_key_or_injected_client(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        AnthropicPlanner()
