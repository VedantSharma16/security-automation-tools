"""Tests for the live agent loop, using a scripted fake Anthropic client so the
suite runs without the optional `anthropic` dependency or network access.
"""

import pytest

from soc_agent.agent import InvestigationIncomplete, SocAgent


class _ToolUseBlock:
    type = "tool_use"

    def __init__(self, id, name, input):
        self.id = id
        self.name = name
        self.input = input


class _TextBlock:
    type = "text"

    def __init__(self, text):
        self.text = text


class _FakeResponse:
    def __init__(self, content):
        self.content = content


class _FakeMessages:
    def __init__(self, responses):
        self._responses = iter(responses)

    def create(self, **kwargs):
        return next(self._responses)


class _FakeClient:
    def __init__(self, responses):
        self.messages = _FakeMessages(responses)


def _agent_with_scripted_responses(responses, max_steps=8):
    agent = SocAgent(api_key=None, max_steps=max_steps)
    agent._client = _FakeClient(responses)  # bypass needing the real SDK installed
    return agent


def test_agent_without_api_key_and_no_env_is_offline(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    agent = SocAgent(api_key=None)
    assert agent.is_live is False


def test_investigate_without_live_client_uses_offline_planner(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    agent = SocAgent(api_key=None)
    verdict, transcript = agent.investigate("Routine benign login for user 'jsmith' from 198.51.100.20.")
    assert verdict.severity in ("low", "medium", "high", "critical")
    assert transcript[-1].tool == "finish_investigation"


def test_live_loop_dispatches_tool_calls_and_stops_on_finish():
    responses = [
        _FakeResponse([_ToolUseBlock("t1", "check_ioc_reputation", {"indicator": "203.0.113.77"})]),
        _FakeResponse(
            [
                _ToolUseBlock(
                    "t2",
                    "finish_investigation",
                    {
                        "severity": "critical",
                        "summary": "Known-malicious IP authenticated successfully.",
                        "key_indicators": ["203.0.113.77"],
                        "matched_techniques": ["T1110 Brute Force"],
                        "recommended_actions": ["Isolate the host."],
                    },
                )
            ]
        ),
    ]
    agent = _agent_with_scripted_responses(responses)
    assert agent.is_live is True

    verdict, transcript = agent.investigate("SSH brute force from 203.0.113.77")

    assert verdict.severity == "critical"
    assert verdict.key_indicators == ["203.0.113.77"]
    assert verdict.steps_taken == 2
    assert [step.tool for step in transcript] == ["check_ioc_reputation", "finish_investigation"]


def test_live_loop_raises_when_step_budget_exhausted_without_finishing():
    # The agent keeps calling a tool but never calls finish_investigation.
    responses = [
        _FakeResponse([_ToolUseBlock(f"t{i}", "check_ioc_reputation", {"indicator": "1.2.3.4"})])
        for i in range(5)
    ]
    agent = _agent_with_scripted_responses(responses, max_steps=3)

    with pytest.raises(InvestigationIncomplete):
        agent.investigate("Some alert that never gets resolved.")


def test_live_loop_raises_when_model_never_calls_a_tool():
    responses = [_FakeResponse([_TextBlock("I don't think this needs investigation.")])]
    agent = _agent_with_scripted_responses(responses)

    with pytest.raises(InvestigationIncomplete):
        agent.investigate("An alert the model refuses to triage with tools.")


def test_multiple_tool_uses_in_one_response_are_all_dispatched():
    responses = [
        _FakeResponse(
            [
                _ToolUseBlock("t1", "check_ioc_reputation", {"indicator": "203.0.113.77"}),
                _ToolUseBlock("t2", "lookup_attack_technique", {"keywords": "brute force"}),
            ]
        ),
        _FakeResponse(
            [
                _ToolUseBlock(
                    "t3",
                    "finish_investigation",
                    {
                        "severity": "high",
                        "summary": "s",
                        "key_indicators": [],
                        "matched_techniques": [],
                        "recommended_actions": [],
                    },
                )
            ]
        ),
    ]
    agent = _agent_with_scripted_responses(responses)
    verdict, transcript = agent.investigate("alert text")
    assert verdict.steps_taken == 3
    assert {step.tool for step in transcript[:2]} == {"check_ioc_reputation", "lookup_attack_technique"}
