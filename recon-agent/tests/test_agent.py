from __future__ import annotations

from types import SimpleNamespace

from recon_agent import dns_client
from recon_agent.agent import OFFLINE_PLAN, ReconAgent
from recon_agent.tools import ToolRegistry


def _fake_resolver(domain, record_type):
    return dns_client.DnsResult(domain=domain, record_type=record_type, records=[])


def _offline_registry():
    class NullOpener:
        def open(self, request, timeout=None):
            raise OSError("network disabled in tests")

    class NullConn:
        pass

    def failing_connect(host, port, timeout):
        raise OSError("network disabled in tests")

    return ToolRegistry(
        "example.com",
        dns_resolver=_fake_resolver,
        http_opener=NullOpener(),
        tls_connect=failing_connect,
    )


def test_offline_agent_runs_full_plan_and_scores_risk():
    agent = ReconAgent("example.com", registry=_offline_registry())

    report = agent.run()

    assert agent.is_live is False
    assert report.is_live is False
    assert [(t.tool, t.arguments) for t in report.trace] == OFFLINE_PLAN
    assert report.risk is not None
    assert "offline heuristic summary" in report.narrative


def _text_block(text):
    return SimpleNamespace(type="text", text=text)


def _tool_use_block(name, arguments, call_id="call_1"):
    return SimpleNamespace(type="tool_use", name=name, input=arguments, id=call_id)


class FakeLiveClient:
    """Simulates anthropic.Anthropic for the tool-use loop, response by response."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


def _make_live_agent(responses, registry=None):
    agent = ReconAgent("example.com", registry=registry or _offline_registry())
    agent._client = FakeLiveClient(responses)
    return agent


def test_live_agent_calls_tool_then_returns_final_summary():
    responses = [
        SimpleNamespace(
            stop_reason="tool_use",
            content=[_tool_use_block("dns_lookup", {"record_type": "A"})],
        ),
        SimpleNamespace(stop_reason="end_turn", content=[_text_block("Target has one A record.")]),
    ]
    agent = _make_live_agent(responses)

    report = agent.run()

    assert report.is_live is True
    assert len(report.trace) == 1
    assert report.trace[0].tool == "dns_lookup"
    assert report.narrative == "Target has one A record."


def test_live_agent_falls_back_offline_on_api_failure_with_no_prior_tool_calls():
    class RaisingClient:
        def __init__(self):
            self.messages = SimpleNamespace(create=self._create)

        def _create(self, **kwargs):
            raise RuntimeError("connection reset")

    agent = ReconAgent("example.com", registry=_offline_registry())
    agent._client = RaisingClient()

    report = agent.run()

    assert len(report.trace) == len(OFFLINE_PLAN)
    assert "LLM call failed" in report.narrative


def test_live_agent_stops_after_max_iterations():
    responses = [
        SimpleNamespace(
            stop_reason="tool_use",
            content=[_tool_use_block("dns_lookup", {"record_type": "A"}, call_id=f"call_{i}")],
        )
        for i in range(3)
    ]
    agent = _make_live_agent(responses)
    agent.max_iterations = 3

    report = agent.run()

    assert len(report.trace) == 3
    assert "max tool-call iterations" in report.narrative


def test_live_agent_records_tool_error_without_crashing():
    responses = [
        SimpleNamespace(
            stop_reason="tool_use",
            content=[_tool_use_block("not_a_real_tool", {})],
        ),
        SimpleNamespace(stop_reason="end_turn", content=[_text_block("done")]),
    ]
    agent = _make_live_agent(responses)

    report = agent.run()

    assert report.narrative == "done"
    assert report.trace == []  # the failed dispatch never produced a trace entry
