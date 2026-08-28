from recon_agent.agent import run_agent
from recon_agent.planner import AgentAction, DeterministicPlanner, Finish
from recon_agent.tools import ToolBox, ToolResult


class _StubPlanner:
    def __init__(self, actions):
        self._actions = list(actions)

    def plan(self, step_index, transcript):
        if not self._actions:
            return Finish("done")
        return self._actions.pop(0)


class _StubToolBox:
    def dns_lookup(self, host):
        return ToolResult("dns_lookup", True, {"host": host, "addresses": ["1.2.3.4"]})


def test_run_agent_executes_actions_until_finish():
    planner = _StubPlanner([AgentAction("dns_lookup", {"host": "example.com"}, "resolve")])
    run = run_agent("https://example.com", _StubToolBox(), planner, max_steps=5)
    assert len(run.steps) == 1
    assert run.steps[0].result.ok
    assert run.finished_reason == "done"


def test_run_agent_stops_at_max_steps():
    class InfinitePlanner:
        def plan(self, step_index, transcript):
            return AgentAction("dns_lookup", {"host": "example.com"}, "again")

    run = run_agent("https://example.com", _StubToolBox(), InfinitePlanner(), max_steps=3)
    assert len(run.steps) == 3
    assert run.finished_reason == "Reached max step budget."


def test_run_agent_handles_unknown_tool_gracefully():
    planner = _StubPlanner([AgentAction("not_a_real_tool", {}, "oops")])
    run = run_agent("https://example.com", _StubToolBox(), planner, max_steps=2)
    assert len(run.steps) == 1
    assert not run.steps[0].result.ok
    assert "Unknown tool" in run.steps[0].result.error


def test_run_agent_handles_bad_kwargs_gracefully():
    planner = _StubPlanner([AgentAction("dns_lookup", {"unexpected_kwarg": 1}, "oops")])
    run = run_agent("https://example.com", _StubToolBox(), planner, max_steps=2)
    assert not run.steps[0].result.ok
    assert "Invalid arguments" in run.steps[0].result.error


def test_deterministic_planner_full_end_to_end_run_uses_real_toolbox():
    toolbox = ToolBox(
        resolve=lambda host: ["93.184.216.34"],
        http_get=lambda url, timeout: (
            (200, {"Content-Type": "text/html"}, b"User-agent: *\nDisallow: /admin\n")
            if url.endswith("robots.txt")
            else (200, {"Content-Type": "text/html"}, b"")
        ),
        tcp_connect=lambda host, port, timeout: port == 443,
        tls_info=lambda host, port, timeout: {"protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "cert": {}},
    )
    planner = DeterministicPlanner("https://example.com")
    run = run_agent("https://example.com", toolbox, planner, max_steps=10)

    tools_called = [step.action.tool for step in run.steps]
    assert tools_called == [
        "dns_lookup",
        "fetch_headers",
        "grade_security_headers",
        "fetch_robots_txt",
        "check_tls",
        "port_scan",
    ]
    assert run.finished_reason == "All planned recon steps are complete."
    assert all(step.result.ok for step in run.steps)
