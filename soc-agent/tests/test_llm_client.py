import sys

from soc_agent import llm_client
from tests.fake_anthropic import FakeBlock, FakeResponse, make_fake_anthropic_module


def test_is_available_false_without_key(monkeypatch):
    assert llm_client.is_available(None) is False
    assert llm_client.is_available("") is False


def test_is_available_false_when_sdk_not_installed(monkeypatch):
    # In this dev environment the real `anthropic` package is intentionally
    # not installed (it's an optional `[llm]` extra), so with no fake module
    # injected into sys.modules, the real import fails.
    monkeypatch.delitem(sys.modules, "anthropic", raising=False)
    assert llm_client.is_available("sk-fake-key") is False


def test_is_available_true_with_key_and_fake_sdk(monkeypatch):
    monkeypatch.setitem(sys.modules, "anthropic", make_fake_anthropic_module([]))
    assert llm_client.is_available("sk-fake-key") is True


def test_resolve_api_key_prefers_explicit_over_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    assert llm_client.resolve_api_key("explicit-key") == "explicit-key"
    assert llm_client.resolve_api_key(None) == "env-key"


def test_parse_final_answer_valid_json():
    text = (
        '{"verdict": "malicious", "severity": "high", "confidence": "high", '
        '"summary": "bad stuff", "recommended_actions": ["isolate host"]}'
    )
    parsed = llm_client._parse_final_answer(text)
    assert parsed["verdict"] == "malicious"
    assert parsed["recommended_actions"] == ["isolate host"]


def test_parse_final_answer_strips_markdown_fences():
    text = '```json\n{"verdict": "benign", "severity": "low", "confidence": "high", "summary": "ok", "recommended_actions": []}\n```'
    parsed = llm_client._parse_final_answer(text)
    assert parsed["verdict"] == "benign"


def test_parse_final_answer_rejects_missing_keys():
    assert llm_client._parse_final_answer('{"verdict": "benign"}') is None


def test_parse_final_answer_rejects_non_json():
    assert llm_client._parse_final_answer("I think this is fine.") is None


def test_run_live_agent_calls_tool_then_returns_parsed_verdict(monkeypatch):
    tool_call_response = FakeResponse(
        content=[
            FakeBlock(type="text", text="I should check this IP's reputation first."),
            FakeBlock(
                type="tool_use",
                name="lookup_ip_reputation",
                input={"ip": "185.220.101.1"},
                id="tu_1",
            ),
        ]
    )
    final_response = FakeResponse(
        content=[
            FakeBlock(
                type="text",
                text=(
                    '{"verdict": "malicious", "severity": "high", "confidence": "high", '
                    '"summary": "Known Tor exit node used for C2.", '
                    '"recommended_actions": ["Isolate host", "Block IP"]}'
                ),
            )
        ]
    )
    monkeypatch.setitem(
        sys.modules, "anthropic", make_fake_anthropic_module([tool_call_response, final_response])
    )

    steps, verdict = llm_client.run_live_agent("alert text", api_key="sk-fake", max_steps=6)

    assert len(steps) == 1
    assert steps[0]["action"] == "lookup_ip_reputation"
    assert steps[0]["observation"]["verdict"] == "malicious"
    assert verdict["verdict"] == "malicious"
    assert verdict["recommended_actions"] == ["Isolate host", "Block IP"]


def test_run_live_agent_returns_none_verdict_when_step_budget_exhausted(monkeypatch):
    def endless_tool_call():
        return FakeResponse(
            content=[
                FakeBlock(
                    type="tool_use",
                    name="lookup_ip_reputation",
                    input={"ip": "8.8.8.8"},
                    id="tu_x",
                )
            ]
        )

    monkeypatch.setitem(
        sys.modules, "anthropic", make_fake_anthropic_module([endless_tool_call() for _ in range(3)])
    )

    steps, verdict = llm_client.run_live_agent("alert text", api_key="sk-fake", max_steps=3)

    assert len(steps) == 3
    assert verdict is None


def test_run_live_agent_handles_unknown_tool_name_gracefully(monkeypatch):
    response = FakeResponse(
        content=[FakeBlock(type="tool_use", name="not_a_real_tool", input={}, id="tu_z")]
    )
    final_response = FakeResponse(
        content=[
            FakeBlock(
                type="text",
                text='{"verdict": "inconclusive", "severity": "low", "confidence": "low", "summary": "n/a", "recommended_actions": []}',
            )
        ]
    )
    monkeypatch.setitem(sys.modules, "anthropic", make_fake_anthropic_module([response, final_response]))

    steps, verdict = llm_client.run_live_agent("alert text", api_key="sk-fake", max_steps=6)

    assert steps[0]["observation"]["error"].startswith("unknown tool")
    assert verdict["verdict"] == "inconclusive"
