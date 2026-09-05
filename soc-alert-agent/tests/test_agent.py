"""Tests for the agent facade and the LLM tool-calling loop.

The LLM loop is tested against a fake `anthropic` module injected into
`sys.modules` — no network access or real API key required. Only the
Messages API call is faked; every tool dispatch underneath it (reputation
lookup, asset criticality, etc.) runs for real against the bundled demo
data, so the test also exercises the tool-loop wiring itself.
"""

from __future__ import annotations

import sys
import types

from soc_agent.agent import run_agent
from soc_agent.models import Alert
from soc_agent.tools import ToolRegistry

ALERT = Alert(
    alert_id="ALT-1001",
    timestamp="2026-09-04T02:14:11Z",
    source="EDR",
    host="web-prod-03",
    description="Outbound beacon-like connection to 203.0.113.77.",
    src_ip="203.0.113.77",
)


class _TextBlock:
    type = "text"

    def __init__(self, text):
        self.text = text


class _ToolUseBlock:
    type = "tool_use"

    def __init__(self, name, input_, block_id):
        self.name = name
        self.input = input_
        self.id = block_id


class _FakeResponse:
    def __init__(self, content):
        self.content = content


class _FakeAnthropicClient:
    """Stands in for `anthropic.Anthropic()`; `.messages` is itself so `.messages.create()` works."""

    def __init__(self, responses, api_key=None):
        self._responses = iter(responses)
        self.messages = self

    def create(self, **kwargs):
        return next(self._responses)


def _install_fake_anthropic(monkeypatch, responses):
    module = types.ModuleType("anthropic")
    module.Anthropic = lambda api_key=None: _FakeAnthropicClient(responses)
    monkeypatch.setitem(sys.modules, "anthropic", module)


def test_facade_uses_deterministic_backend_by_default():
    result = run_agent(ALERT, ToolRegistry(alerts=[ALERT.to_dict()]), use_llm=False)
    assert result.backend == "deterministic"


def test_facade_falls_back_to_deterministic_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = run_agent(ALERT, ToolRegistry(alerts=[ALERT.to_dict()]), use_llm=True)
    assert result.backend == "deterministic"


def test_llm_loop_dispatches_tools_and_stops_on_terminal_call(monkeypatch):
    responses = [
        _FakeResponse(
            [
                _TextBlock("Checking indicator reputation first."),
                _ToolUseBlock("lookup_ioc_reputation", {"indicator": "203.0.113.77"}, "tool_1"),
            ]
        ),
        _FakeResponse(
            [_ToolUseBlock("escalate", {"reason": "Confirmed known-malicious C2 indicator."}, "tool_2")]
        ),
    ]
    _install_fake_anthropic(monkeypatch, responses)

    result = run_agent(ALERT, ToolRegistry(alerts=[ALERT.to_dict()]), use_llm=True, api_key="fake-key")

    assert result.backend == "llm"
    assert result.verdict == "escalate"
    assert len(result.steps) == 2
    assert result.steps[0].tool_name == "lookup_ioc_reputation"
    assert result.steps[0].tool_result["known_malicious"] is True
    assert result.steps[0].thought == "Checking indicator reputation first."
    assert result.steps[1].tool_name == "escalate"


def test_llm_loop_defaults_to_monitor_when_no_tool_is_called(monkeypatch):
    responses = [_FakeResponse([_TextBlock("I am not sure what to do here.")])]
    _install_fake_anthropic(monkeypatch, responses)

    result = run_agent(ALERT, ToolRegistry(alerts=[ALERT.to_dict()]), use_llm=True, api_key="fake-key")

    assert result.backend == "llm"
    assert result.verdict == "monitor"
    assert "no terminal tool call" in result.reason


def test_llm_loop_defaults_to_monitor_when_step_budget_exhausted(monkeypatch):
    non_terminal = _FakeResponse(
        [_ToolUseBlock("get_asset_criticality", {"host": "web-prod-03"}, "tool_x")]
    )
    _install_fake_anthropic(monkeypatch, [non_terminal] * 3)

    result = run_agent(
        ALERT, ToolRegistry(alerts=[ALERT.to_dict()]), use_llm=True, api_key="fake-key", max_steps=3
    )

    assert result.backend == "llm"
    assert result.verdict == "monitor"
    assert "step budget" in result.reason
    assert len(result.steps) == 3


def test_llm_loop_falls_back_to_deterministic_on_api_failure(monkeypatch):
    module = types.ModuleType("anthropic")

    def _raise_client(api_key=None):
        raise RuntimeError("simulated network failure")

    module.Anthropic = _raise_client
    monkeypatch.setitem(sys.modules, "anthropic", module)

    result = run_agent(ALERT, ToolRegistry(alerts=[ALERT.to_dict()]), use_llm=True, api_key="fake-key")

    assert result.backend == "deterministic"
    assert result.note is not None
    assert "simulated network failure" in result.note
