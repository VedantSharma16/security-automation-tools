import json

import pytest

from recon_agent.agent import Planner, ReconSession, TOOL_REGISTRY, run_recon
from recon_agent.dns_recon import DnsResult, SubdomainResult
from recon_agent.http_recon import HttpResult, TlsResult
from recon_agent.port_scan import PortResult


def _patch_all(monkeypatch, *, dns_resolved=True):
    dns_result = DnsResult(hostname="example.com", resolved=dns_resolved, ip="1.2.3.4" if dns_resolved else None, error=None if dns_resolved else "NXDOMAIN")
    monkeypatch.setattr("recon_agent.agent.resolve_host", lambda target: dns_result)
    monkeypatch.setattr(
        "recon_agent.agent.enumerate_subdomains",
        lambda domain, words, limit=None: [SubdomainResult(subdomain="www.example.com", ip="1.2.3.5")],
    )
    monkeypatch.setattr(
        "recon_agent.agent.scan_ports",
        lambda ip, ports, timeout: [PortResult(port=22, open=True, banner="SSH-2.0-OpenSSH")],
    )
    monkeypatch.setattr(
        "recon_agent.agent.fetch_headers",
        lambda url, timeout=5.0: HttpResult(url=url, status=200, headers={"server": "nginx"}, error=None),
    )
    monkeypatch.setattr(
        "recon_agent.agent.fetch_tls_certificate",
        lambda hostname, timeout=5.0: TlsResult(hostname=hostname, port=443, fetched=True, not_after="Jan 1 00:00:00 2030 GMT", days_remaining=1500, issuer="Test CA", error=None),
    )


def test_offline_run_visits_all_tools_when_dns_resolves(monkeypatch):
    _patch_all(monkeypatch, dns_resolved=True)
    run = run_recon("example.com", allow_subdomain_enum=True, wordlist=["www"], max_steps=10)
    assert run.session.ran() == set(TOOL_REGISTRY)
    assert run.planner_live is False


def test_offline_run_stops_early_when_dns_fails(monkeypatch):
    _patch_all(monkeypatch, dns_resolved=False)
    run = run_recon("nonexistent.invalid", allow_subdomain_enum=True, wordlist=["www"], max_steps=10)
    assert run.session.ran() == {"dns_lookup"}


def test_offline_run_skips_subdomain_enum_when_disabled(monkeypatch):
    _patch_all(monkeypatch, dns_resolved=True)
    run = run_recon("example.com", allow_subdomain_enum=False, wordlist=[], max_steps=10)
    assert "subdomain_enum" not in run.session.ran()
    assert run.session.ran() == set(TOOL_REGISTRY) - {"subdomain_enum"}


def test_max_steps_caps_tool_calls(monkeypatch):
    _patch_all(monkeypatch, dns_resolved=True)
    run = run_recon("example.com", allow_subdomain_enum=True, wordlist=["www"], max_steps=2)
    assert len(run.session.steps) == 2


class FakeTextBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class FakeResponse:
    def __init__(self, text):
        self.content = [FakeTextBlock(text)]


class FakeAnthropicClient:
    def __init__(self, script):
        self.script = list(script)

    @property
    def messages(self):
        return self

    def create(self, **kwargs):
        return FakeResponse(self.script.pop(0))


def test_live_planner_follows_llm_selected_actions(monkeypatch):
    _patch_all(monkeypatch, dns_resolved=True)
    planner = Planner()
    planner._client = FakeAnthropicClient(
        [
            json.dumps({"action": "dns_lookup", "reason": "start"}),
            json.dumps({"action": "finish", "reason": "enough signal"}),
        ]
    )
    assert planner.is_live is True

    run = run_recon("example.com", allow_subdomain_enum=True, wordlist=["www"], max_steps=10, planner=planner)
    assert run.session.ran() == {"dns_lookup"}
    assert run.planner_live is True


def test_live_planner_falls_back_on_malformed_response(monkeypatch):
    _patch_all(monkeypatch, dns_resolved=True)
    planner = Planner()
    planner._client = FakeAnthropicClient(["not json at all"])

    action, reason = planner.next_action(ReconSession(target="example.com"), allow_subdomain_enum=True)
    assert action == "dns_lookup"
    assert "fallback" in reason


def test_live_planner_falls_back_on_repeated_or_unknown_action(monkeypatch):
    session = ReconSession(target="example.com")
    session.record("dns_lookup", {"resolved": True, "ip": "1.2.3.4"})

    planner = Planner()
    planner._client = FakeAnthropicClient([json.dumps({"action": "dns_lookup", "reason": "repeat"})])

    action, reason = planner.next_action(session, allow_subdomain_enum=True)
    # dns_lookup already ran, so it's not in `available`; planner should fall back.
    assert action == "subdomain_enum"
