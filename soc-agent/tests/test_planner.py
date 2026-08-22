from soc_agent.llm_client import LLMClient
from soc_agent.models import Incident, ToolCall, ToolStep
from soc_agent.planner import FINISH, AgentState, DeterministicPlanner, LLMPlanner
from soc_agent.tools import ToolRegistry


def _state(**incident_kwargs) -> AgentState:
    return AgentState(incident=Incident(incident_id="T1", **incident_kwargs))


def test_planner_checks_all_indicators_before_anything_else():
    state = _state(indicators=["1.1.1.1", "2.2.2.2"], process_name="powershell.exe")
    planner = DeterministicPlanner()

    first = planner.decide(state)
    assert first == ToolCall("threat_intel_lookup", {"indicator": "1.1.1.1"})

    state.steps.append(ToolStep(call=first, result={"indicator": "1.1.1.1", "is_malicious": False}))
    second = planner.decide(state)
    assert second == ToolCall("threat_intel_lookup", {"indicator": "2.2.2.2"})


def test_planner_moves_to_process_then_asset_then_baseline():
    state = _state(hostname="DC01", user="asingh", process_name="powershell.exe", command_line="powershell.exe -enc AAAA")
    planner = DeterministicPlanner()

    action = planner.decide(state)
    assert action.tool == "process_reputation_lookup"
    state.steps.append(ToolStep(call=action, result={"is_suspicious": False, "matched_patterns": []}))

    action = planner.decide(state)
    assert action.tool == "asset_criticality_lookup"
    state.steps.append(ToolStep(call=action, result={"criticality": "critical"}))

    action = planner.decide(state)
    assert action.tool == "user_baseline_check"


def test_planner_finishes_early_when_nothing_suspicious_found():
    state = _state(hostname="WKS-01", user="jsmith", process_name="outlook.exe")
    planner = DeterministicPlanner()

    action = planner.decide(state)
    state.steps.append(ToolStep(call=action, result={"is_suspicious": False, "matched_patterns": []}))
    action = planner.decide(state)
    state.steps.append(ToolStep(call=action, result={"criticality": "low"}))
    action = planner.decide(state)
    state.steps.append(ToolStep(call=action, result={"is_deviation": False}))

    # Nothing suspicious anywhere -> planner should skip ATT&CK lookup and finish.
    final_action = planner.decide(state)
    assert final_action.tool == FINISH


def test_planner_runs_attack_lookup_when_something_suspicious_found():
    state = _state(process_name="powershell.exe", command_line="powershell.exe -enc AAAA")
    planner = DeterministicPlanner()

    action = planner.decide(state)
    assert action.tool == "process_reputation_lookup"
    state.steps.append(
        ToolStep(call=action, result={"is_suspicious": True, "matched_patterns": ["Base64-encoded PowerShell command"]})
    )

    action = planner.decide(state)
    assert action.tool == "attack_technique_lookup"
    assert "Base64-encoded PowerShell command" in action.arguments["keywords"]


def test_planner_finishes_immediately_on_empty_incident():
    state = _state()
    assert DeterministicPlanner().decide(state).tool == FINISH


def test_planner_is_not_live():
    assert DeterministicPlanner().is_live is False


def test_llm_planner_falls_back_to_deterministic_without_api_key():
    registry = ToolRegistry()
    planner = LLMPlanner(registry, llm_client=LLMClient(api_key=None))
    assert planner.is_live is False

    state = _state(indicators=["1.1.1.1"])
    action = planner.decide(state)
    assert action == ToolCall("threat_intel_lookup", {"indicator": "1.1.1.1"})
