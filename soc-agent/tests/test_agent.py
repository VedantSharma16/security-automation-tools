"""Tests for the live tool-calling loop, using a fake Anthropic-shaped client
so the ReAct control flow (call tool -> feed result back -> repeat until
submit_verdict) is exercised without any network access or API key.
"""

from types import SimpleNamespace

from soc_agent.agent import SocAgent
from soc_agent.models import Alert


def _block(type_, **kwargs):
    return SimpleNamespace(type=type_, **kwargs)


def _alert() -> Alert:
    return Alert.from_dict(
        {
            "alert_id": "ALERT-TEST-LIVE",
            "title": "Suspicious outbound connection",
            "description": "Host contacted update-service-cdn.net repeatedly.",
            "source_ip": "10.20.4.17",
            "destination": "update-service-cdn.net",
            "hostname": "WKS-DEV-14",
            "raw_indicators": ["update-service-cdn.net"],
        }
    )


class ScriptedClient:
    """Fake client returning a pre-scripted sequence of tool-use responses."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

        class _Messages:
            def create(inner_self, **kwargs):
                # Snapshot the messages list — the caller keeps mutating the
                # same list object after this call returns.
                self.calls.append({**kwargs, "messages": list(kwargs["messages"])})
                return self._responses.pop(0)

        self.messages = _Messages()


def test_agent_calls_tool_then_submits_verdict():
    responses = [
        SimpleNamespace(
            content=[
                _block("tool_use", id="t1", name="ioc_lookup", input={"indicator": "update-service-cdn.net"}),
            ]
        ),
        SimpleNamespace(
            content=[
                _block(
                    "tool_use",
                    id="t2",
                    name="submit_verdict",
                    input={
                        "verdict": "malicious",
                        "confidence": 0.9,
                        "recommended_action": "Isolate host.",
                        "rationale": "Known-malicious domain.",
                    },
                )
            ]
        ),
    ]
    agent = SocAgent(client=ScriptedClient(responses))
    assert agent.is_live is True

    result = agent.investigate(_alert(), max_steps=5)

    assert result.mode == "live"
    assert result.verdict.verdict == "malicious"
    assert len(result.trace) == 2
    assert result.trace[0].tool == "ioc_lookup"
    assert result.trace[0].output["found"] is True
    assert result.trace[1].tool == "submit_verdict"


def test_agent_passes_real_tool_output_back_to_the_model():
    responses = [
        SimpleNamespace(
            content=[_block("tool_use", id="t1", name="ioc_lookup", input={"indicator": "update-service-cdn.net"})]
        ),
        SimpleNamespace(
            content=[
                _block(
                    "tool_use",
                    id="t2",
                    name="submit_verdict",
                    input={"verdict": "malicious", "confidence": 0.8, "recommended_action": "x", "rationale": "y"},
                )
            ]
        ),
    ]
    client = ScriptedClient(responses)
    agent = SocAgent(client=client)
    agent.investigate(_alert())

    # second call's messages must include a tool_result reflecting the real ioc_lookup output
    second_call_messages = client.calls[1]["messages"]
    tool_result_message = second_call_messages[-1]
    assert tool_result_message["role"] == "user"
    assert tool_result_message["content"][0]["type"] == "tool_result"
    assert "malicious" in tool_result_message["content"][0]["content"]


def test_agent_gives_up_after_max_steps_without_verdict():
    # Every response calls a lookup tool but never submits a verdict.
    responses = [
        SimpleNamespace(content=[_block("tool_use", id=f"t{i}", name="ioc_lookup", input={"indicator": "x.com"})])
        for i in range(3)
    ]
    agent = SocAgent(client=ScriptedClient(responses))

    result = agent.investigate(_alert(), max_steps=3)

    assert result.mode == "live-max-steps"
    assert result.verdict.verdict == "inconclusive"
    assert len(result.trace) == 3


def test_agent_falls_back_to_offline_when_no_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    agent = SocAgent()
    assert agent.is_live is False

    result = agent.investigate(_alert())
    assert result.mode == "offline"


def test_agent_falls_back_offline_when_live_call_raises():
    class BrokenClient:
        class messages:
            @staticmethod
            def create(**kwargs):
                raise RuntimeError("network unreachable")

    agent = SocAgent(client=BrokenClient())
    result = agent.investigate(_alert())

    assert result.mode == "offline-after-live-error"
    assert "network unreachable" in result.verdict.rationale
