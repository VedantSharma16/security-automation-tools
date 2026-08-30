from recon_agent.agent import (
    DEFAULT_MAX_STEPS,
    Action,
    AgentState,
    LLMPolicy,
    ReconAgent,
    deterministic_next_action,
)
from recon_agent.models import ProbeResult, TLSResult


def _ok_probe(url):
    return ProbeResult(url=url, ok=True, status_code=200, headers={})


def _failed_probe(url):
    return ProbeResult(url=url, ok=False, error="refused")


def test_deterministic_policy_full_happy_path():
    """https reachable -> analyze -> tls -> finish, in that order, no wasted http probe."""

    def probe_url_fn(url, timeout=5.0):
        return _ok_probe(url)

    def probe_tls_fn(host, port=443, timeout=5.0):
        return TLSResult(host=host, port=port, ok=True, version="TLSv1.3")

    agent = ReconAgent()
    state = agent.run("example.com", probe_url_fn=probe_url_fn, probe_tls_fn=probe_tls_fn)

    tool_sequence = [s.tool for s in state.steps]
    assert tool_sequence == ["probe_https", "analyze_headers", "probe_tls", "finish"]
    assert state.done is True
    assert "http" not in state.probes  # HTTPS worked, so no need to fall back


def test_deterministic_policy_falls_back_to_http_when_https_unreachable():
    def probe_url_fn(url, timeout=5.0):
        if url.startswith("https://"):
            return _failed_probe(url)
        return _ok_probe(url)

    agent = ReconAgent()
    state = agent.run("example.com", probe_url_fn=probe_url_fn, probe_tls_fn=lambda *a, **k: None)

    tool_sequence = [s.tool for s in state.steps]
    assert tool_sequence == ["probe_https", "probe_http", "analyze_headers", "finish"]
    # TLS is skipped entirely — no point checking a cert on a host that never answered HTTPS.
    assert state.tls is None


def test_agent_never_exceeds_max_steps_even_with_a_broken_policy():
    def never_finishes(state):
        return Action("probe_https", {"host": state.host})

    agent = ReconAgent(policy=never_finishes, max_steps=3)
    state = agent.run(
        "example.com",
        probe_url_fn=lambda url, timeout=5.0: _ok_probe(url),
        probe_tls_fn=lambda *a, **k: None,
    )

    assert len(state.steps) == 3
    assert state.done is False


def test_findings_accumulate_from_analyze_headers_step():
    def probe_url_fn(url, timeout=5.0):
        return ProbeResult(url=url, ok=True, status_code=200, headers={})  # no security headers at all

    def probe_tls_fn(host, port=443, timeout=5.0):
        return TLSResult(host=host, port=port, ok=True, version="TLSv1.2")

    agent = ReconAgent()
    state = agent.run("example.com", probe_url_fn=probe_url_fn, probe_tls_fn=probe_tls_fn)

    assert len(state.findings) > 0
    assert all(f.source_url == "https://example.com" for f in state.findings)


def test_llm_policy_without_api_key_behaves_like_deterministic():
    policy = LLMPolicy(api_key=None)
    assert policy.is_live is False

    state = AgentState(host="example.com")
    action = policy(state)
    assert action.tool == deterministic_next_action(state).tool == "probe_https"


def test_default_max_steps_is_reasonable():
    # A regression guard: this should stay small enough that a runaway/buggy
    # policy can never turn the agent into an unbounded scanner.
    assert 0 < DEFAULT_MAX_STEPS <= 10
