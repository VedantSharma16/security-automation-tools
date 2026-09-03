import sys
import types

from recon_agent import agent as agent_mod
from recon_agent.http_fingerprint import HttpFingerprint
from recon_agent.port_scan import PortResult


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

    def create(self, **kwargs):
        return self._responses.pop(0)


class FakeAnthropicClient:
    def __init__(self, api_key, responses):
        self.messages = FakeMessages(responses)


def install_fake_anthropic(monkeypatch, responses):
    fake_module = types.ModuleType("anthropic")
    fake_module.Anthropic = lambda api_key: FakeAnthropicClient(api_key, responses)
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)


def test_deterministic_pipeline_used_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(agent_mod.dns_recon, "resolve", lambda d: "1.2.3.4")
    monkeypatch.setattr(agent_mod.dns_recon, "enumerate_subdomains", lambda d, wl, **kw: {})
    monkeypatch.setattr(agent_mod.port_scan, "scan_ports", lambda host, ports=None, **kw: [])

    run = agent_mod.run_recon("example.com", wordlist=["www"])

    assert run.ip == "1.2.3.4"
    assert "offline deterministic pipeline" in run.agent_narrative
    assert run.tool_calls_made == ["resolve_and_enumerate_subdomains", "scan_ports"]


def test_deterministic_pipeline_fingerprints_web_ports(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(agent_mod.dns_recon, "resolve", lambda d: "1.2.3.4")
    monkeypatch.setattr(agent_mod.dns_recon, "enumerate_subdomains", lambda d, wl, **kw: {})
    monkeypatch.setattr(
        agent_mod.port_scan, "scan_ports", lambda host, ports=None, **kw: [PortResult(443, True, "https")]
    )
    monkeypatch.setattr(
        agent_mod.http_fingerprint,
        "fingerprint_http",
        lambda host, port: HttpFingerprint(port=port, scheme="https", status=200),
    )

    run = agent_mod.run_recon("example.com", wordlist=["www"])

    assert run.tool_calls_made == [
        "resolve_and_enumerate_subdomains",
        "scan_ports",
        "fingerprint_web_services",
    ]
    assert run.http_fingerprints[0].port == 443


def test_agent_loop_calls_tools_then_returns_model_narrative(monkeypatch):
    monkeypatch.setattr(agent_mod.dns_recon, "resolve", lambda d: "1.2.3.4")
    monkeypatch.setattr(
        agent_mod.dns_recon, "enumerate_subdomains", lambda d, wl, **kw: {"www.example.com": "1.1.1.1"}
    )
    monkeypatch.setattr(
        agent_mod.port_scan, "scan_ports", lambda host, ports=None, **kw: [PortResult(443, True, "https")]
    )

    tool_call_1 = FakeBlock("tool_use", id="1", name="resolve_and_enumerate_subdomains", input={"domain": "example.com"})
    tool_call_2 = FakeBlock("tool_use", id="2", name="scan_ports", input={"host": "example.com"})
    final_text = FakeBlock("text", text="Recon complete: one HTTPS host found, no immediate red flags.")

    responses = [
        FakeResponse([tool_call_1]),
        FakeResponse([tool_call_2]),
        FakeResponse([final_text]),
    ]
    install_fake_anthropic(monkeypatch, responses)

    run = agent_mod.run_recon("example.com", wordlist=["www"], api_key="fake-key")

    assert run.tool_calls_made == ["resolve_and_enumerate_subdomains", "scan_ports"]
    assert run.ip == "1.2.3.4"
    assert run.subdomains == {"www.example.com": "1.1.1.1"}
    assert run.open_ports[0].port == 443
    assert run.agent_narrative == "Recon complete: one HTTPS host found, no immediate red flags."


def test_agent_loop_falls_back_when_api_call_fails(monkeypatch):
    monkeypatch.setattr(agent_mod.dns_recon, "resolve", lambda d: "1.2.3.4")
    monkeypatch.setattr(agent_mod.dns_recon, "enumerate_subdomains", lambda d, wl, **kw: {})
    monkeypatch.setattr(agent_mod.port_scan, "scan_ports", lambda host, ports=None, **kw: [])

    class FailingMessages:
        def create(self, **kwargs):
            raise RuntimeError("network down")

    class FailingClient:
        def __init__(self, api_key):
            self.messages = FailingMessages()

    fake_module = types.ModuleType("anthropic")
    fake_module.Anthropic = FailingClient
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)

    run = agent_mod.run_recon("example.com", wordlist=["www"], api_key="fake-key")

    assert "LLM call failed" in run.agent_narrative
    assert run.ip == "1.2.3.4"


def test_agent_loop_stops_after_max_turns(monkeypatch):
    monkeypatch.setattr(agent_mod.dns_recon, "resolve", lambda d: "1.2.3.4")
    monkeypatch.setattr(agent_mod.dns_recon, "enumerate_subdomains", lambda d, wl, **kw: {})
    monkeypatch.setattr(agent_mod.port_scan, "scan_ports", lambda host, ports=None, **kw: [])

    tool_call = FakeBlock("tool_use", id="1", name="scan_ports", input={"host": "example.com"})
    responses = [FakeResponse([tool_call]) for _ in range(agent_mod.MAX_AGENT_TURNS)]
    install_fake_anthropic(monkeypatch, responses)

    run = agent_mod.run_recon("example.com", wordlist=["www"], api_key="fake-key")

    assert "max tool-call turn limit" in run.agent_narrative
    assert len(run.tool_calls_made) == agent_mod.MAX_AGENT_TURNS
