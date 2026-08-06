from types import SimpleNamespace

from recon_agent import planner
from recon_agent.models import ToolResult


def make_registry():
    calls = []

    def make_tool(name):
        def _run():
            calls.append(name)
            return ToolResult(tool=name, data={"ok": True}, findings=[])

        return _run

    registry = {name: make_tool(name) for name in planner.STATIC_PLAN}
    return registry, calls


class FakeResponse:
    def __init__(self, content, stop_reason):
        self.content = content
        self.stop_reason = stop_reason


class FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


class FakeClient:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


def tool_use_block(name, call_id="call-1"):
    return SimpleNamespace(type="tool_use", name=name, id=call_id, input={})


def text_block(text):
    return SimpleNamespace(type="text", text=text)


def test_static_plan_runs_all_tools_in_order():
    registry, calls = make_registry()
    results = planner.run_static(registry)
    assert calls == list(planner.STATIC_PLAN)
    assert [r.tool for r in results] == list(planner.STATIC_PLAN)


def test_run_agentic_falls_back_to_static_plan_when_no_client(monkeypatch):
    monkeypatch.setattr(planner, "_build_client", lambda: None)
    registry, calls = make_registry()

    results, narrative = planner.run_agentic(registry, "example.com", client=None)

    assert narrative == ""
    assert [r.tool for r in results] == list(planner.STATIC_PLAN)


def test_run_agentic_calls_tools_the_model_requests_and_captures_final_narrative():
    registry, calls = make_registry()
    responses = [
        FakeResponse([tool_use_block("dns_lookup", "call-1")], stop_reason="tool_use"),
        FakeResponse([tool_use_block("http_headers", "call-2")], stop_reason="tool_use"),
        FakeResponse([text_block("Posture looks reasonable.")], stop_reason="end_turn"),
    ]
    client = FakeClient(responses)

    results, narrative = planner.run_agentic(registry, "example.com", client=client)

    assert calls == ["dns_lookup", "http_headers"]
    assert [r.tool for r in results] == ["dns_lookup", "http_headers"]
    assert narrative == "Posture looks reasonable."


def test_run_agentic_does_not_call_the_same_tool_twice():
    registry, calls = make_registry()
    responses = [
        FakeResponse([tool_use_block("dns_lookup", "call-1")], stop_reason="tool_use"),
        FakeResponse([tool_use_block("dns_lookup", "call-2")], stop_reason="tool_use"),
        FakeResponse([text_block("done")], stop_reason="end_turn"),
    ]
    client = FakeClient(responses)

    results, _ = planner.run_agentic(registry, "example.com", client=client)

    assert calls == ["dns_lookup"]
    assert len(results) == 1


def test_run_agentic_respects_max_steps():
    registry, _ = make_registry()
    responses = [
        FakeResponse([tool_use_block("dns_lookup", f"call-{i}")], stop_reason="tool_use") for i in range(10)
    ]
    client = FakeClient(responses)

    planner.run_agentic(registry, "example.com", max_steps=2, client=client)

    assert len(client.messages.calls) == 2
