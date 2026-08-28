import pytest

from recon_agent.agent import TranscriptStep
from recon_agent.planner import AgentAction, DeterministicPlanner, Finish, LLMPlanner
from recon_agent.tools import ToolResult


def _step(index, tool, ok=True, data=None, error=None):
    return TranscriptStep(index, AgentAction(tool, {}, ""), ToolResult(tool, ok, data or {}, error))


def test_first_step_is_dns_lookup():
    planner = DeterministicPlanner("https://example.com")
    action = planner.plan(0, [])
    assert action.tool == "dns_lookup"
    assert action.kwargs == {"host": "example.com"}


def test_sequence_skips_tls_over_plain_http():
    planner = DeterministicPlanner("http://example.com")
    transcript = [
        _step(0, "dns_lookup"),
        _step(1, "fetch_headers", data={"headers": {}}),
        _step(2, "grade_security_headers"),
        _step(3, "fetch_robots_txt"),
    ]
    action = planner.plan(4, transcript)
    assert action.tool == "port_scan"


def test_https_target_runs_tls_check_before_port_scan():
    planner = DeterministicPlanner("https://example.com")
    transcript = [
        _step(0, "dns_lookup"),
        _step(1, "fetch_headers", data={"headers": {}}),
        _step(2, "grade_security_headers"),
        _step(3, "fetch_robots_txt"),
    ]
    action = planner.plan(4, transcript)
    assert action.tool == "check_tls"


def test_skips_header_grading_if_fetch_failed():
    planner = DeterministicPlanner("https://example.com")
    transcript = [
        _step(0, "dns_lookup"),
        _step(1, "fetch_headers", ok=False, error="timed out"),
    ]
    action = planner.plan(2, transcript)
    assert action.tool == "fetch_robots_txt"


def test_finishes_after_full_sequence():
    planner = DeterministicPlanner("https://example.com:8443")
    transcript = [
        _step(0, "dns_lookup"),
        _step(1, "fetch_headers", data={"headers": {}}),
        _step(2, "grade_security_headers"),
        _step(3, "fetch_robots_txt"),
        _step(4, "check_tls"),
        _step(5, "port_scan"),
    ]
    result = planner.plan(6, transcript)
    assert isinstance(result, Finish)


def test_port_scan_ports_include_target_port():
    planner = DeterministicPlanner("https://example.com:8443")
    transcript = [
        _step(0, "dns_lookup"),
        _step(1, "fetch_headers", data={"headers": {}}),
        _step(2, "grade_security_headers"),
        _step(3, "fetch_robots_txt"),
        _step(4, "check_tls"),
    ]
    action = planner.plan(5, transcript)
    assert action.tool == "port_scan"
    assert 8443 in action.kwargs["ports"]


def test_llm_planner_without_api_key_is_not_live(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    planner = LLMPlanner("https://example.com")
    assert planner.is_live is False


def test_llm_planner_plan_without_client_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    planner = LLMPlanner("https://example.com")
    with pytest.raises(RuntimeError):
        planner.plan(0, [])


class _FakeBlock:
    def __init__(self, type_, name=None, input_=None, text=None):
        self.type = type_
        self.name = name
        self.input = input_
        self.text = text


class _FakeResponse:
    def __init__(self, content):
        self.content = content


class _FakeMessages:
    def __init__(self, response):
        self._response = response

    def create(self, **kwargs):
        return self._response


class _FakeClient:
    def __init__(self, content):
        self.messages = _FakeMessages(_FakeResponse(content))


def test_llm_planner_parses_tool_use_block():
    planner = LLMPlanner("https://example.com")
    planner._client = _FakeClient([_FakeBlock("tool_use", name="dns_lookup", input_={"host": "example.com"})])
    action = planner.plan(0, [])
    assert action.tool == "dns_lookup"
    assert action.kwargs == {"host": "example.com"}


def test_llm_planner_parses_finish_block():
    planner = LLMPlanner("https://example.com")
    planner._client = _FakeClient([_FakeBlock("tool_use", name="finish", input_={"reason": "done"})])
    result = planner.plan(0, [])
    assert isinstance(result, Finish)
    assert result.thought == "done"
