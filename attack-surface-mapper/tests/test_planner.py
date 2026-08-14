from __future__ import annotations

from types import SimpleNamespace

from conftest import make_result

from asmapper.fetcher import FetchResult
from asmapper.planner import MAX_AGENT_STEPS, Planner


def text_block(text: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=text)


def tool_use_block(name: str, call_id: str) -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", name=name, id=call_id, input={})


def response_with(*blocks) -> SimpleNamespace:
    return SimpleNamespace(content=list(blocks))


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


def _target_result():
    return make_result(
        "https://example.com",
        status=200,
        headers={"Server": "nginx"},
        body="<html>hello</html>",
    )


# ---- offline / deterministic path ----


def test_no_api_key_uses_offline_planner(fake_fetcher):
    fake_fetcher.register("https://example.com", _target_result())
    planner = Planner(api_key=None)
    assert not planner.is_live
    state = planner.run("https://example.com", fetch_fn=fake_fetcher)
    assert state.planner_mode == "offline"
    tools_run = [step.tool for step in state.trace]
    assert tools_run == ["run_header_audit", "run_recon_files_scan", "run_fingerprint"]


def test_offline_planner_skips_exposure_checks_by_default(fake_fetcher):
    fake_fetcher.register("https://example.com", _target_result())
    planner = Planner(force_offline=True, allow_exposure_checks=False)
    state = planner.run("https://example.com", fetch_fn=fake_fetcher)
    assert "run_exposure_check" not in [step.tool for step in state.trace]


def test_offline_planner_runs_exposure_checks_when_enabled(fake_fetcher):
    fake_fetcher.register("https://example.com", _target_result())
    planner = Planner(force_offline=True, allow_exposure_checks=True)
    state = planner.run("https://example.com", fetch_fn=fake_fetcher)
    assert "run_exposure_check" in [step.tool for step in state.trace]


def test_force_offline_ignores_api_key(fake_fetcher):
    fake_fetcher.register("https://example.com", _target_result())
    planner = Planner(api_key="sk-fake-key", force_offline=True)
    assert not planner.is_live


def test_unreachable_target_short_circuits(fake_fetcher):
    fake_fetcher.register("https://example.com", FetchResult(url="https://example.com", status=None, error="timeout"))
    planner = Planner(force_offline=True)
    state = planner.run("https://example.com", fetch_fn=fake_fetcher)
    assert state.trace[0].tool == "none"
    assert state.findings == []


# ---- agentic path (fake Anthropic client, no network/API calls) ----


def _agentic_planner(responses, allow_exposure_checks=False):
    planner = Planner(force_offline=True, allow_exposure_checks=allow_exposure_checks)
    planner._client = FakeClient(responses)  # simulate a live client without touching the real SDK
    return planner


def test_agentic_loop_calls_chosen_tools_and_stops_on_final_text(fake_fetcher):
    fake_fetcher.register("https://example.com", _target_result())
    responses = [
        response_with(tool_use_block("run_header_audit", "call_1")),
        response_with(tool_use_block("run_fingerprint", "call_2")),
        response_with(text_block("Moderate attack surface; verify TLS config next.")),
    ]
    planner = _agentic_planner(responses)
    state = planner.run("https://example.com", fetch_fn=fake_fetcher)

    assert state.planner_mode == "agentic"
    assert [step.tool for step in state.trace] == ["run_header_audit", "run_fingerprint"]
    assert state.agent_assessment == "Moderate attack surface; verify TLS config next."
    assert any(f.category == "headers" for f in state.findings)


def test_agentic_loop_skips_duplicate_tool_calls(fake_fetcher):
    fake_fetcher.register("https://example.com", _target_result())
    responses = [
        response_with(tool_use_block("run_header_audit", "call_1")),
        response_with(tool_use_block("run_header_audit", "call_2")),  # duplicate, should be skipped
        response_with(text_block("done")),
    ]
    planner = _agentic_planner(responses)
    state = planner.run("https://example.com", fetch_fn=fake_fetcher)

    assert [step.tool for step in state.trace] == ["run_header_audit"]


def test_agentic_loop_never_offers_exposure_tool_unless_enabled(fake_fetcher):
    fake_fetcher.register("https://example.com", _target_result())
    responses = [response_with(text_block("done"))]
    planner = _agentic_planner(responses, allow_exposure_checks=False)
    planner.run("https://example.com", fetch_fn=fake_fetcher)

    offered_tools = {t["name"] for t in planner._client.messages.calls[0]["tools"]}
    assert "run_exposure_check" not in offered_tools


def test_agentic_loop_offers_exposure_tool_when_enabled(fake_fetcher):
    fake_fetcher.register("https://example.com", _target_result())
    responses = [response_with(text_block("done"))]
    planner = _agentic_planner(responses, allow_exposure_checks=True)
    planner.run("https://example.com", fetch_fn=fake_fetcher)

    offered_tools = {t["name"] for t in planner._client.messages.calls[0]["tools"]}
    assert "run_exposure_check" in offered_tools


def test_agentic_loop_ignores_hallucinated_unoffered_tool(fake_fetcher):
    fake_fetcher.register("https://example.com", _target_result())
    responses = [
        response_with(tool_use_block("run_exposure_check", "call_1")),  # not offered; must be skipped, not executed
        response_with(text_block("done")),
    ]
    planner = _agentic_planner(responses, allow_exposure_checks=False)
    state = planner.run("https://example.com", fetch_fn=fake_fetcher)

    assert state.findings == []
    assert state.trace == []


def test_agentic_loop_stops_at_step_cap(fake_fetcher):
    fake_fetcher.register("https://example.com", _target_result())
    # every response keeps calling the same tool; after the first it's always a "duplicate" skip,
    # so the loop never sees a text-only response and must hit the hard step cap.
    responses = [response_with(tool_use_block("run_header_audit", f"call_{i}")) for i in range(MAX_AGENT_STEPS)]
    planner = _agentic_planner(responses)
    state = planner.run("https://example.com", fetch_fn=fake_fetcher)

    assert len(planner._client.messages.calls) == MAX_AGENT_STEPS
    assert "step cap" in state.agent_assessment
