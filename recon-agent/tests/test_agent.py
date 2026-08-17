"""Tests for the agentic tool-use loop and the offline fallback.

The live path is exercised by swapping in a FakeAnthropicClient that mimics
the shape of the real SDK's ``messages.create`` response (content blocks
with a ``.type`` of ``tool_use``/``text``) — no real API key or network
call is ever involved.
"""

from __future__ import annotations

from recon_agent.agent import ReconAgent, ReconReport


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
        self.create_calls = []

    def create(self, **kwargs):
        self.create_calls.append(kwargs)
        return self._responses.pop(0)


class FakeAnthropicClient:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


def _agent_with_fake_client(responses, tool_impl=None, max_steps=6):
    agent = ReconAgent(api_key=None, max_steps=max_steps, tool_impl=tool_impl)
    agent._client = FakeAnthropicClient(responses)
    return agent


def test_offline_mode_when_no_api_key():
    agent = ReconAgent(api_key=None)
    assert agent.is_live is False


def test_offline_run_calls_every_tool_once_and_builds_a_report():
    calls = []

    def make_tool(name, result):
        def _tool(**kwargs):
            calls.append(name)
            return result
        return _tool

    tool_impl = {
        "dns_lookup": make_tool("dns_lookup", {"domain": "example.com", "resolved": True, "addresses": ["1.2.3.4"]}),
        "subdomain_enum": make_tool("subdomain_enum", {"domain": "example.com", "checked": 1, "discovered": []}),
        "http_probe": make_tool("http_probe", {"host": "example.com", "reachable": True, "missing_security_headers": []}),
        "tls_probe": make_tool("tls_probe", {"host": "example.com", "reachable": True, "protocol": "TLSv1.3", "days_until_expiry": 200}),
        "whois_lookup": make_tool("whois_lookup", {"domain": "example.com", "available": False, "note": "n/a"}),
    }
    agent = ReconAgent(api_key=None, tool_impl=tool_impl)

    report = agent.run("example.com")

    assert isinstance(report, ReconReport)
    assert report.agent_backed is False
    assert report.severity == "info"
    assert sorted(calls) == sorted(tool_impl.keys())
    assert "offline deterministic pipeline" in report.narrative


def test_agentic_run_follows_tool_use_then_final_text():
    dns_result = {"domain": "example.com", "resolved": True, "addresses": ["1.2.3.4"]}
    http_result = {"host": "example.com", "reachable": True, "missing_security_headers": ["Content-Security-Policy"]}

    responses = [
        FakeResponse([FakeBlock("tool_use", id="t1", name="dns_lookup", input={"domain": "example.com"})]),
        FakeResponse([FakeBlock("tool_use", id="t2", name="http_probe", input={"host": "example.com"})]),
        FakeResponse([FakeBlock("text", text="Attack surface looks mostly clean; one header gap found.")]),
    ]
    tool_impl = {"dns_lookup": lambda **kw: dns_result, "http_probe": lambda **kw: http_result}
    agent = _agent_with_fake_client(responses, tool_impl=tool_impl)

    report = agent.run("example.com")

    assert report.agent_backed is True
    assert report.steps_taken == 3
    assert report.tool_results["dns_lookup"] == [dns_result]
    assert report.tool_results["http_probe"] == [http_result]
    assert report.narrative == "Attack surface looks mostly clean; one header gap found."
    assert any(f.category == "missing-security-headers" for f in report.findings)


def test_agentic_run_stops_at_max_steps_and_still_reports_findings():
    tool_call = FakeResponse([FakeBlock("tool_use", id="t", name="dns_lookup", input={"domain": "example.com"})])
    responses = [tool_call, tool_call, tool_call]  # model never stops calling tools
    tool_impl = {"dns_lookup": lambda **kw: {"domain": "example.com", "resolved": True, "addresses": ["1.2.3.4"]}}
    agent = _agent_with_fake_client(responses, tool_impl=tool_impl, max_steps=3)

    report = agent.run("example.com")

    assert report.agent_backed is True
    assert report.steps_taken == 3
    assert "step budget" in report.narrative
    assert len(report.tool_results["dns_lookup"]) == 3


def test_agentic_run_records_unknown_tool_as_error_without_crashing():
    responses = [
        FakeResponse([FakeBlock("tool_use", id="t1", name="nmap_full_scan", input={})]),
        FakeResponse([FakeBlock("text", text="Done.")]),
    ]
    agent = _agent_with_fake_client(responses, tool_impl={})

    report = agent.run("example.com")

    assert report.tool_results["nmap_full_scan"][0]["error"].startswith("unknown tool")
    assert report.narrative == "Done."


def test_agent_run_falls_back_to_offline_when_live_call_raises():
    class ExplodingMessages:
        def create(self, **kwargs):
            raise RuntimeError("connection reset")

    class ExplodingClient:
        def __init__(self):
            self.messages = ExplodingMessages()

    tool_impl = {
        "dns_lookup": lambda **kw: {"domain": "example.com", "resolved": True, "addresses": ["1.2.3.4"]},
        "subdomain_enum": lambda **kw: {"domain": "example.com", "checked": 0, "discovered": []},
        "http_probe": lambda **kw: {"host": "example.com", "reachable": True, "missing_security_headers": []},
        "tls_probe": lambda **kw: {"host": "example.com", "reachable": True, "protocol": "TLSv1.3", "days_until_expiry": 200},
        "whois_lookup": lambda **kw: {"domain": "example.com", "available": False, "note": "n/a"},
    }
    agent = ReconAgent(api_key=None, tool_impl=tool_impl)
    agent._client = ExplodingClient()

    report = agent.run("example.com")

    assert report.agent_backed is False
    assert "offline fallback used" in report.narrative
    assert "connection reset" in report.narrative
