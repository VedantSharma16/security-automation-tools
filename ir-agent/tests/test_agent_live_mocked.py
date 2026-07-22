"""Tests for the live, LLM-driven tool-use loop using a fake Anthropic client.

The real ``anthropic`` package isn't a hard dependency (see pyproject.toml's
``llm`` extra), so these tests never import it — they stub out
``IncidentResponseAgent._client`` directly with an object shaped like the
part of the SDK's response the agent loop actually reads (``.content``,
``.stop_reason``), which is enough to exercise the loop's control flow
without any network access.
"""

from dataclasses import dataclass, field

import pytest

from ir_agent.agent import IncidentResponseAgent


@dataclass
class FakeResponse:
    content: list
    stop_reason: str = "tool_use"


class FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


class FakeClient:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


def _make_agent(responses, max_tool_turns=8):
    agent = IncidentResponseAgent(api_key=None, max_tool_turns=max_tool_turns)
    agent._client = FakeClient(responses)
    return agent


FINAL_REPORT_INPUT = {
    "severity": "high",
    "summary": "Brute-force SSH activity from a known-bad IP culminated in a successful login.",
    "key_indicators": ["91.219.236.18"],
    "attack_techniques": ["T1110", "T1078"],
    "recommended_actions": ["Isolate the host.", "Reset the compromised account's password."],
}


def test_live_loop_calls_tools_then_finalizes():
    responses = [
        FakeResponse(
            content=[
                {
                    "type": "tool_use",
                    "id": "call_1",
                    "name": "extract_iocs",
                    "input": {"text": "Failed password for root from 91.219.236.18"},
                }
            ]
        ),
        FakeResponse(
            content=[
                {
                    "type": "tool_use",
                    "id": "call_2",
                    "name": "submit_incident_report",
                    "input": FINAL_REPORT_INPUT,
                }
            ]
        ),
    ]
    agent = _make_agent(responses)

    result = agent.investigate("Failed password for root from 91.219.236.18")

    assert result.mode == "live"
    assert result.severity == "high"
    assert result.key_indicators == ["91.219.236.18"]
    assert len(result.transcript) == 1
    assert result.transcript[0].tool == "extract_iocs"
    assert result.transcript[0].output["ips"][0]["value"] == "91.219.236.18"

    # Two API calls were made: one that returned the tool_use, one that returned the final report.
    assert len(agent._client.messages.calls) == 2


def test_live_loop_dispatches_multiple_tools_before_finalizing():
    responses = [
        FakeResponse(
            content=[
                {"type": "tool_use", "id": "call_1", "name": "extract_iocs", "input": {"text": "some text"}}
            ]
        ),
        FakeResponse(
            content=[
                {
                    "type": "tool_use",
                    "id": "call_2",
                    "name": "map_attack_techniques",
                    "input": {"text": "brute force", "top_k": 3},
                }
            ]
        ),
        FakeResponse(
            content=[
                {"type": "tool_use", "id": "call_3", "name": "submit_incident_report", "input": FINAL_REPORT_INPUT}
            ]
        ),
    ]
    agent = _make_agent(responses)

    result = agent.investigate("some text")

    assert [call.tool for call in result.transcript] == ["extract_iocs", "map_attack_techniques"]
    assert result.mode == "live"


def test_live_loop_falls_back_to_offline_if_model_never_submits():
    # Every turn calls extract_iocs and never submit_incident_report — the loop
    # should exhaust max_tool_turns and fall back to the deterministic pipeline.
    responses = [
        FakeResponse(
            content=[
                {"type": "tool_use", "id": f"call_{i}", "name": "extract_iocs", "input": {"text": "x"}}
            ]
        )
        for i in range(3)
    ]
    agent = _make_agent(responses, max_tool_turns=3)

    result = agent.investigate("Contact attacker@evil.com about 91.219.236.18.")

    assert result.mode == "live-fallback"
    # The offline synthesis still ran on the real incident text.
    assert result.severity in ("low", "medium", "high", "critical")


def test_live_loop_falls_back_when_model_returns_plain_text_only():
    responses = [FakeResponse(content=[{"type": "text", "text": "I looked into it."}], stop_reason="end_turn")]
    agent = _make_agent(responses)

    result = agent.investigate("Routine maintenance window completed with no issues.")

    assert result.mode == "live-fallback"
    assert result.severity == "low"


def test_investigate_catches_client_exceptions_and_falls_back():
    class ExplodingMessages:
        def create(self, **kwargs):
            raise RuntimeError("network error")

    class ExplodingClient:
        def __init__(self):
            self.messages = ExplodingMessages()

    agent = IncidentResponseAgent(api_key=None)
    agent._client = ExplodingClient()

    result = agent.investigate("Routine maintenance window completed with no issues.")
    assert result.mode == "live-fallback"
    assert result.severity == "low"
