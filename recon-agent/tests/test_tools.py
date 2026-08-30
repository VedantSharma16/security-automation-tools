from recon_agent.agent import AgentState
from recon_agent.models import ProbeResult, TLSResult
from recon_agent.tools import TOOLS, tool_schemas


def _state(**overrides):
    kwargs = dict(host="example.com", timeout=1.0)
    kwargs.update(overrides)
    return AgentState(**kwargs)


def test_all_expected_tools_registered():
    assert set(TOOLS) == {"probe_https", "probe_http", "probe_tls", "analyze_headers", "finish"}


def test_tool_schemas_are_well_formed():
    schemas = tool_schemas()
    assert len(schemas) == len(TOOLS)
    for schema in schemas:
        assert schema["name"] in TOOLS
        assert schema["description"]
        assert schema["input_schema"]["type"] == "object"


def test_probe_https_uses_injected_fn():
    calls = []

    def fake_probe_url(url, timeout=5.0):
        calls.append((url, timeout))
        return ProbeResult(url=url, ok=True, status_code=200, headers={})

    state = _state(probe_url_fn=fake_probe_url)
    result = TOOLS["probe_https"].func(state, {"host": "example.com"})

    assert calls == [("https://example.com", 1.0)]
    assert result.status_code == 200


def test_probe_http_uses_injected_fn():
    def fake_probe_url(url, timeout=5.0):
        return ProbeResult(url=url, ok=True, status_code=200, headers={})

    state = _state(probe_url_fn=fake_probe_url)
    result = TOOLS["probe_http"].func(state, {"host": "example.com"})
    assert result.url == "http://example.com"


def test_probe_tls_uses_injected_fn_and_default_port():
    calls = []

    def fake_probe_tls(host, port=443, timeout=5.0):
        calls.append((host, port, timeout))
        return TLSResult(host=host, port=port, ok=True, version="TLSv1.3")

    state = _state(probe_tls_fn=fake_probe_tls)
    result = TOOLS["probe_tls"].func(state, {"host": "example.com"})

    assert calls == [("example.com", 443, 1.0)]
    assert result.version == "TLSv1.3"


def test_analyze_headers_looks_up_probe_by_key():
    state = _state()
    state.probes["https"] = ProbeResult(
        url="https://example.com", ok=True, status_code=200, headers={}
    )
    findings = TOOLS["analyze_headers"].func(state, {"probe_key": "https"})
    assert any(f.id == "hdr-no-hsts" for f in findings)


def test_analyze_headers_missing_probe_key_returns_empty():
    state = _state()
    findings = TOOLS["analyze_headers"].func(state, {"probe_key": "nope"})
    assert findings == []


def test_finish_echoes_summary():
    state = _state()
    result = TOOLS["finish"].func(state, {"summary": "done"})
    assert result == {"summary": "done"}
