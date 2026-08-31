from __future__ import annotations

from recon_agent import dns_client
from recon_agent.tools import TOOL_SPECS, ToolError, ToolRegistry


def _fake_resolver(domain, record_type):
    return dns_client.DnsResult(
        domain=domain,
        record_type=record_type,
        records=[dns_client.DnsRecord(domain, record_type, 300, "1.2.3.4")],
    )


class FakeHttpOpener:
    def open(self, request, timeout=None):
        raise AssertionError("should not be called in this test")


def test_tool_specs_have_required_fields():
    names = {spec["name"] for spec in TOOL_SPECS}
    assert names == {"dns_lookup", "http_headers", "robots_check", "tls_check"}
    for spec in TOOL_SPECS:
        assert "description" in spec and spec["description"]
        assert "input_schema" in spec


def test_dns_lookup_records_result_on_registry():
    registry = ToolRegistry("example.com", dns_resolver=_fake_resolver)

    result = registry.dns_lookup(record_type="A")

    assert result["records"][0]["value"] == "1.2.3.4"
    assert len(registry.dns_results) == 1
    assert registry.dns_results[0].record_type == "A"


def test_dispatch_routes_to_correct_tool():
    registry = ToolRegistry("example.com", dns_resolver=_fake_resolver)

    result = registry.dispatch("dns_lookup", {"record_type": "MX"})

    assert result["record_type"] == "MX"
    assert registry.dns_results[0].record_type == "MX"


def test_dispatch_defaults_missing_arguments():
    registry = ToolRegistry("example.com", dns_resolver=_fake_resolver)

    result = registry.dispatch("dns_lookup", {})

    assert result["record_type"] == "A"


def test_dispatch_unknown_tool_raises():
    registry = ToolRegistry("example.com")

    try:
        registry.dispatch("port_scan", {})
        assert False, "expected ToolError"
    except ToolError as exc:
        assert "port_scan" in str(exc)


def test_tls_check_uses_injected_connect():
    class FakeConn:
        def getpeercert(self, binary_form=False):
            return None

        def version(self):
            return "TLSv1.3"

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def close(self):
            pass

    registry = ToolRegistry("example.com", tls_connect=lambda host, port, timeout: FakeConn())

    result = registry.tls_check()

    assert result["connected"] is True
    assert registry.tls_finding.connected is True
