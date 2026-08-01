from types import SimpleNamespace

import pytest

from soc_orchestrator import agent, tools
from soc_orchestrator.case import load_case
from soc_orchestrator.tools import ToolResult


# ---------------------------------------------------------------------------
# DeterministicPlanner: the offline fallback used whenever no LLM is available.
# ---------------------------------------------------------------------------


def test_deterministic_planner_calls_one_tool_per_matching_file_plus_process_hunt(tmp_path, monkeypatch):
    (tmp_path / "auth.log").write_text("...", encoding="utf-8")
    (tmp_path / "alert.txt").write_text("...", encoding="utf-8")
    case = load_case(tmp_path)

    calls = []
    monkeypatch.setitem(tools.DISPATCH, "run_log_triage", lambda logfile: calls.append(("log", logfile)) or ToolResult(tool="run_log_triage", ok=True))
    monkeypatch.setitem(tools.DISPATCH, "run_ioc_triage", lambda alert_file: calls.append(("ioc", alert_file)) or ToolResult(tool="run_ioc_triage", ok=True))
    monkeypatch.setitem(tools.DISPATCH, "run_process_hunt", lambda: calls.append(("proc",)) or ToolResult(tool="run_process_hunt", ok=True))

    results, narrative = agent.DeterministicPlanner().run(case)

    assert narrative is None
    assert len(results) == 3
    assert {c[0] for c in calls} == {"log", "ioc", "proc"}


def test_deterministic_planner_skips_tools_with_no_matching_evidence(tmp_path, monkeypatch):
    case = load_case(tmp_path)  # empty case dir

    monkeypatch.setitem(tools.DISPATCH, "run_process_hunt", lambda: ToolResult(tool="run_process_hunt", ok=True))

    results, _ = agent.DeterministicPlanner().run(case)

    assert [r.tool for r in results] == ["run_process_hunt"]


# ---------------------------------------------------------------------------
# LLMPlanner: exercises the real tool-use loop shape against a fake client so
# tests never make network calls or require the `anthropic` package.
# ---------------------------------------------------------------------------


class _Block:
    def __init__(self, type, **kw):
        self.type = type
        for k, v in kw.items():
            setattr(self, k, v)


class _Response:
    def __init__(self, content):
        self.content = content


class _FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        # Snapshot messages at call time -- the real list keeps mutating after
        # this call returns, so store a shallow copy rather than the live ref.
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})
        return self._responses.pop(0)


class _FakeClient:
    def __init__(self, responses):
        self.messages = _FakeMessages(responses)


def test_llm_planner_executes_tool_use_then_returns_final_narrative(tmp_path, monkeypatch):
    (tmp_path / "auth.log").write_text("...", encoding="utf-8")
    case = load_case(tmp_path)

    monkeypatch.setitem(
        tools.DISPATCH,
        "run_log_triage",
        lambda logfile: ToolResult(tool="run_log_triage", ok=True, severity="high"),
    )

    responses = [
        _Response([_Block("tool_use", id="t1", name="run_log_triage", input={"logfile": str(tmp_path / "auth.log")})]),
        _Response([_Block("text", text="Brute force detected, high severity.")]),
    ]
    client = _FakeClient(responses)
    planner = agent.LLMPlanner(client=client)

    results, narrative = planner.run(case)

    assert len(results) == 1
    assert results[0].tool == "run_log_triage"
    assert narrative == "Brute force detected, high severity."
    # second call must include the tool_result from the first turn
    second_call_messages = client.messages.calls[1]["messages"]
    assert second_call_messages[-1]["role"] == "user"
    assert second_call_messages[-1]["content"][0]["type"] == "tool_result"


def test_llm_planner_unknown_tool_name_is_reported_not_raised(tmp_path):
    case = load_case(tmp_path)
    responses = [
        _Response([_Block("tool_use", id="t1", name="not_a_real_tool", input={})]),
        _Response([_Block("text", text="done")]),
    ]
    planner = agent.LLMPlanner(client=_FakeClient(responses))

    results, narrative = planner.run(case)

    assert results[0].ok is False
    assert results[0].error == "unknown tool"


def test_llm_planner_gives_up_after_max_turns_without_conclusion(tmp_path, monkeypatch):
    case = load_case(tmp_path)
    monkeypatch.setitem(tools.DISPATCH, "run_process_hunt", lambda: ToolResult(tool="run_process_hunt", ok=True))
    monkeypatch.setattr(agent, "MAX_AGENT_TURNS", 2)

    responses = [
        _Response([_Block("tool_use", id="t1", name="run_process_hunt", input={})])
        for _ in range(2)
    ]
    planner = agent.LLMPlanner(client=_FakeClient(responses))

    results, narrative = planner.run(case)

    assert narrative is None
    assert len(results) == 2


# ---------------------------------------------------------------------------
# Planner selection: mirrors the offline-fallback pattern used elsewhere in
# this repo (e.g. logtriage's get_summarizer).
# ---------------------------------------------------------------------------


def test_select_planner_defaults_to_deterministic_without_flag_or_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    planner, llm_backed = agent._select_planner(use_llm=None, model="m")
    assert isinstance(planner, agent.DeterministicPlanner)
    assert llm_backed is False


def test_select_planner_uses_llm_when_key_present_and_no_explicit_choice(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
    monkeypatch.setattr(agent, "LLMPlanner", lambda model, api_key: SimpleNamespace())
    planner, llm_backed = agent._select_planner(use_llm=None, model="m")
    assert llm_backed is True


def test_select_planner_forced_llm_without_key_falls_back(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    planner, llm_backed = agent._select_planner(use_llm=True, model="m")
    assert isinstance(planner, agent.DeterministicPlanner)
    assert llm_backed is False


def test_select_planner_explicit_no_llm_ignores_api_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
    planner, llm_backed = agent._select_planner(use_llm=False, model="m")
    assert isinstance(planner, agent.DeterministicPlanner)
    assert llm_backed is False


# ---------------------------------------------------------------------------
# investigate(): end-to-end wiring, still fully offline.
# ---------------------------------------------------------------------------


def test_investigate_end_to_end_offline(tmp_path, monkeypatch):
    (tmp_path / "auth.log").write_text("...", encoding="utf-8")
    monkeypatch.setitem(
        tools.DISPATCH,
        "run_log_triage",
        lambda logfile: ToolResult(tool="run_log_triage", ok=True, severity="critical", summary="s", data={}),
    )
    monkeypatch.setitem(
        tools.DISPATCH, "run_process_hunt", lambda: ToolResult(tool="run_process_hunt", ok=True, severity="low", data={})
    )

    report = agent.investigate(str(tmp_path), use_llm=False)

    assert report.llm_backed is False
    assert report.overall_severity == "critical"
    assert report.generated_at  # timestamp was stamped
