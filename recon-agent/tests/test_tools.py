import pytest

from recon_agent import tools
from recon_agent.http_fingerprint import HttpFingerprint
from recon_agent.port_scan import PortResult


def test_dispatch_resolve_and_enumerate_subdomains(monkeypatch):
    monkeypatch.setattr(tools.dns_recon, "resolve", lambda domain: "1.2.3.4")
    monkeypatch.setattr(
        tools.dns_recon, "enumerate_subdomains", lambda domain, wordlist, **kw: {"www.example.com": "1.1.1.1"}
    )
    result = tools.dispatch(
        "resolve_and_enumerate_subdomains", {"domain": "example.com"}, wordlist=["www"], ports_list=[80]
    )
    assert result["ip"] == "1.2.3.4"
    assert result["subdomains"] == {"www.example.com": "1.1.1.1"}


def test_dispatch_scan_ports(monkeypatch):
    monkeypatch.setattr(
        tools.port_scan, "scan_ports", lambda host, ports=None, **kw: [PortResult(80, True, "http")]
    )
    result = tools.dispatch("scan_ports", {"host": "1.2.3.4"}, wordlist=[], ports_list=[80])
    assert result["open_ports"] == [{"port": 80, "open": True, "service": "http"}]


def test_dispatch_fingerprint_web_services(monkeypatch):
    fake_fp = HttpFingerprint(port=80, scheme="http", status=200)
    monkeypatch.setattr(tools.http_fingerprint, "fingerprint_http", lambda host, port: fake_fp)
    result = tools.dispatch(
        "fingerprint_web_services", {"host": "1.2.3.4", "ports": [80]}, wordlist=[], ports_list=[]
    )
    assert result["fingerprints"][0]["port"] == 80
    assert result["fingerprints"][0]["status"] == 200


def test_dispatch_unknown_tool_raises_value_error():
    with pytest.raises(ValueError):
        tools.dispatch("not_a_real_tool", {}, wordlist=[], ports_list=[])


def test_tool_schemas_have_required_keys():
    for schema in tools.TOOL_SCHEMAS:
        assert {"name", "description", "input_schema"} <= schema.keys()
        assert schema["input_schema"]["type"] == "object"
