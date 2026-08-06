from recon_agent.tools import build_registry


def test_build_registry_exposes_all_planned_tools():
    registry = build_registry("example.com")
    assert set(registry.keys()) == {"dns_lookup", "http_headers", "tls_certificate", "robots_txt"}
    assert all(callable(fn) for fn in registry.values())
