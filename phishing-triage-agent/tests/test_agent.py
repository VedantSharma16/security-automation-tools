from pathlib import Path

from phishing_agent.agent import PhishingAgent
from phishing_agent.email_parser import parse_eml
from phishing_agent.tools import TOOL_ORDER

FIXTURES = Path(__file__).parent.parent / "examples"


def _load(name):
    return parse_eml((FIXTURES / name).read_bytes())


# -- offline mode ----------------------------------------------------------


def test_offline_agent_is_not_live_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    agent = PhishingAgent(api_key=None)
    assert agent.is_live is False


def test_offline_sweep_flags_phishing_sample():
    agent = PhishingAgent(api_key=None)
    result = agent.investigate(_load("phishing_sample.eml"))

    assert result.live is False
    assert result.verdict == "phishing"
    assert result.confidence > 0.5
    assert len(result.trace) == len(TOOL_ORDER)
    assert [step.tool for step in result.trace] == TOOL_ORDER
    assert any("typosquat" in e or "known-malicious" in e for e in result.key_evidence)


def test_offline_sweep_clears_benign_sample():
    agent = PhishingAgent(api_key=None)
    result = agent.investigate(_load("benign_sample.eml"))

    assert result.verdict == "benign"
    assert len(result.trace) == len(TOOL_ORDER)


def test_agent_result_to_dict_is_json_serializable():
    import json

    agent = PhishingAgent(api_key=None)
    result = agent.investigate(_load("phishing_sample.eml"))
    json.dumps(result.to_dict())  # should not raise


# -- live mode (Anthropic client mocked; no network) ------------------------


class _FakeBlock:
    def __init__(self, type_, name=None, input=None, id=None):
        self.type = type_
        self.name = name
        self.input = input
        self.id = id


class _FakeResponse:
    def __init__(self, content):
        self.content = content


class _ScriptedClient:
    """Fake Anthropic client that returns pre-scripted responses in order."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

        class _Messages:
            def create(inner_self, **kwargs):
                self.calls += 1
                return self._responses.pop(0)

        self.messages = _Messages()


def test_live_agent_executes_tools_then_submit_verdict():
    responses = [
        _FakeResponse([_FakeBlock("tool_use", name="check_authentication", input={}, id="t1")]),
        _FakeResponse([_FakeBlock("tool_use", name="check_url_reputation", input={}, id="t2")]),
        _FakeResponse([
            _FakeBlock(
                "tool_use",
                name="submit_verdict",
                input={
                    "verdict": "phishing",
                    "confidence": 0.92,
                    "reasoning": "Failed auth plus a known-malicious typosquatted URL.",
                    "key_evidence": ["SPF/DKIM/DMARC all failed", "URL matches known-malicious feed"],
                },
                id="t3",
            )
        ]),
    ]
    client = _ScriptedClient(responses)
    agent = PhishingAgent(client=client)

    assert agent.is_live is True

    result = agent.investigate(_load("phishing_sample.eml"))

    assert result.live is True
    assert result.verdict == "phishing"
    assert result.confidence == 0.92
    assert [step.tool for step in result.trace] == ["check_authentication", "check_url_reputation"]
    assert client.calls == 3


def test_live_agent_falls_back_after_max_steps_without_verdict():
    # The "model" keeps calling the same tool forever and never submits a verdict.
    responses = [
        _FakeResponse([_FakeBlock("tool_use", name="check_authentication", input={}, id=f"t{i}")])
        for i in range(5)
    ]
    client = _ScriptedClient(responses)
    agent = PhishingAgent(client=client, max_steps=2)

    result = agent.investigate(_load("phishing_sample.eml"))

    assert result.live is True
    assert result.note is not None and "fallback" in result.note.lower()
    assert len(result.trace) == 2
