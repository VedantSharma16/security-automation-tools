import anthropic
import pytest

from recon_agent.agent import DeterministicPlanner, RunState, run
from recon_agent.llm_client import LLMNotAvailable, LLMPlanner, generate_narrative
from recon_agent.vuln_kb import VulnKnowledgeBase


class FakeBlock:
    def __init__(self, type_, **kwargs):
        self.type = type_
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
        self.calls.append(kwargs)
        return self._responses.pop(0)


class FakeAnthropicClient:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


def test_llm_planner_without_api_key_is_not_live(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    planner = LLMPlanner(api_key=None)
    assert planner.is_live is False


def test_llm_planner_next_action_raises_when_not_live(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    planner = LLMPlanner(api_key=None)
    with pytest.raises(LLMNotAvailable):
        planner.next_action(RunState(target="127.0.0.1"))


def test_llm_planner_returns_tool_call_action(monkeypatch):
    fake_client = FakeAnthropicClient(
        [FakeResponse([FakeBlock("tool_use", name="tcp_connect_scan", input={"host": "127.0.0.1"}, id="tu_1")])]
    )
    monkeypatch.setattr(anthropic, "Anthropic", lambda api_key=None: fake_client)

    planner = LLMPlanner(api_key="fake-key")
    assert planner.is_live is True
    planner.start("127.0.0.1")
    action = planner.next_action(RunState(target="127.0.0.1"))

    assert action.tool == "tcp_connect_scan"
    assert action.args == {"host": "127.0.0.1"}


def test_llm_planner_finish_tool_call_ends_run(monkeypatch):
    fake_client = FakeAnthropicClient([FakeResponse([FakeBlock("tool_use", name="finish", input={}, id="tu_9")])])
    monkeypatch.setattr(anthropic, "Anthropic", lambda api_key=None: fake_client)

    planner = LLMPlanner(api_key="fake-key")
    planner.start("127.0.0.1")
    assert planner.next_action(RunState(target="127.0.0.1")) is None


def test_llm_planner_observe_appends_tool_result(monkeypatch):
    fake_client = FakeAnthropicClient(
        [FakeResponse([FakeBlock("tool_use", name="tcp_connect_scan", input={"host": "127.0.0.1"}, id="tu_1")])]
    )
    monkeypatch.setattr(anthropic, "Anthropic", lambda api_key=None: fake_client)

    planner = LLMPlanner(api_key="fake-key")
    planner.start("127.0.0.1")
    planner.next_action(RunState(target="127.0.0.1"))
    planner.observe({"open_ports": [22]})

    last_message = planner._messages[-1]
    assert last_message["role"] == "user"
    assert last_message["content"][0]["tool_use_id"] == "tu_1"
    assert "22" in last_message["content"][0]["content"]


def test_full_run_driven_by_llm_planner(monkeypatch):
    responses = [
        FakeResponse([FakeBlock("tool_use", name="tcp_connect_scan", input={"host": "127.0.0.1"}, id="tu_1")]),
        FakeResponse([FakeBlock("tool_use", name="grab_banner", input={"host": "127.0.0.1", "port": 22}, id="tu_2")]),
        FakeResponse([FakeBlock("tool_use", name="finish", input={}, id="tu_3")]),
    ]
    fake_client = FakeAnthropicClient(responses)
    monkeypatch.setattr(anthropic, "Anthropic", lambda api_key=None: fake_client)

    def fake_scan(host, ports=None):
        return {"host": host, "ports_scanned": ports or [], "open_ports": [22]}

    def fake_banner(host, port):
        return {"host": host, "port": port, "banner": "SSH-2.0-OpenSSH_7.2", "service": "OpenSSH", "version": "7.2", "error": None}

    planner = LLMPlanner(api_key="fake-key")
    result = run(
        "127.0.0.1",
        planner=planner,
        kb=VulnKnowledgeBase(),
        tool_overrides={"tcp_connect_scan": fake_scan, "grab_banner": fake_banner},
    )

    assert result.completed is True
    assert result.steps_taken == 2
    assert result.open_ports == [22]
    assert result.fingerprints[22]["service"] == "OpenSSH"
    assert len(fake_client.messages.calls) == 3


def test_deterministic_and_llm_planners_share_action_protocol():
    # Sanity check the two planners are interchangeable inputs to run().
    assert DeterministicPlanner().next_action(RunState(target="x")).tool == "tcp_connect_scan"


def test_generate_narrative_offline_fallback_mentions_risk_and_target(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    summary = {"target": "127.0.0.1", "risk": "high", "open_ports": [22, 443], "vuln_matches": []}
    narrative = generate_narrative(summary, api_key=None)
    assert "offline heuristic summary" in narrative
    assert "HIGH" in narrative
    assert "127.0.0.1" in narrative


def test_generate_narrative_offline_fallback_lists_cves(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    summary = {
        "target": "127.0.0.1", "risk": "critical", "open_ports": [21],
        "vuln_matches": [{"cve": "CVE-2011-2523", "severity": "critical", "port": 21, "description": "backdoor"}],
    }
    narrative = generate_narrative(summary, api_key=None)
    assert "CVE-2011-2523" in narrative
