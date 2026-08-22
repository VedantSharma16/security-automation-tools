from soc_agent.llm_client import LLMClient
from soc_agent.models import Incident, ToolCall, ToolStep
from soc_agent.planner import AgentState
from soc_agent.tools import ToolRegistry


class _FakeBlock:
    def __init__(self, type_, name=None, input_=None, text=None):
        self.type = type_
        self.name = name
        self.input = input_
        self.text = text


class _FakeResponse:
    def __init__(self, content):
        self.content = content


class _FakeMessages:
    def __init__(self, response):
        self._response = response

    def create(self, **kwargs):
        return self._response


class _FakeAnthropicClient:
    def __init__(self, response):
        self.messages = _FakeMessages(response)


def test_llm_client_without_api_key_is_not_live(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = LLMClient(api_key=None)
    assert client.is_live is False


def test_plan_next_returns_none_without_api_key():
    client = LLMClient(api_key=None)
    assert client.plan_next(state=None, tool_specs=[]) is None


def test_offline_narrative_mentions_severity_and_indicator():
    client = LLMClient(api_key=None)
    incident = Incident(incident_id="INC-5", hostname="DC01", user="asingh")
    steps = [
        ToolStep(
            call=ToolCall("threat_intel_lookup", {"indicator": "1.2.3.4"}),
            result={"indicator": "1.2.3.4", "is_malicious": True, "confidence": "high"},
        )
    ]
    narrative = client.narrate(incident, steps, "high", ["Isolate the host"])
    assert "offline heuristic narrative" in narrative
    assert "HIGH" in narrative
    assert "1.2.3.4" in narrative
    assert "Isolate the host" in narrative


def test_offline_narrative_handles_no_findings():
    client = LLMClient(api_key=None)
    incident = Incident(incident_id="INC-6")
    narrative = client.narrate(incident, [], "low", ["Monitor and close"])
    assert "LOW" in narrative
    assert "No corroborating evidence" in narrative


def test_plan_next_parses_a_tool_use_response():
    client = LLMClient(api_key=None)
    client._client = _FakeAnthropicClient(
        _FakeResponse([_FakeBlock("tool_use", name="threat_intel_lookup", input_={"indicator": "1.2.3.4"})])
    )
    state = AgentState(incident=Incident(incident_id="INC-7", indicators=["1.2.3.4"]))
    decision = client.plan_next(state, ToolRegistry().specs())
    assert decision == {"tool": "threat_intel_lookup", "arguments": {"indicator": "1.2.3.4"}}


def test_plan_next_parses_finish_investigation():
    client = LLMClient(api_key=None)
    client._client = _FakeAnthropicClient(_FakeResponse([_FakeBlock("tool_use", name="finish_investigation", input_={})]))
    state = AgentState(incident=Incident(incident_id="INC-8"))
    decision = client.plan_next(state, ToolRegistry().specs())
    assert decision == {"tool": "finish_investigation", "arguments": {}}


def test_plan_next_returns_none_when_call_raises():
    class _RaisingMessages:
        def create(self, **kwargs):
            raise RuntimeError("network down")

    class _RaisingClient:
        def __init__(self):
            self.messages = _RaisingMessages()

    client = LLMClient(api_key=None)
    client._client = _RaisingClient()
    state = AgentState(incident=Incident(incident_id="INC-9"))
    assert client.plan_next(state, ToolRegistry().specs()) is None
