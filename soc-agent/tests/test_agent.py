from soc_agent.agent import InvestigationAgent, score_verdict
from soc_agent.models import Incident
from soc_agent.planner import AgentState, ToolCall
from soc_agent.models import ToolStep
from soc_agent.tools import ToolRegistry

FEED = {
    "185.220.101.7": {"confidence": "high", "source": "test-feed", "notes": "tor exit node"},
}
INVENTORY = {"FIN-SQL01": {"criticality": "critical", "owner": "Finance", "environment": "production"}}
BASELINES = {"asingh": ["FIN-SQL01"], "jsmith": ["WKS-0231"]}
TECHNIQUES = [
    {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "keywords": ["powershell", "encoded"], "text": "..."},
    {"id": "T1090", "name": "Proxy", "tactic": "Command and Control", "keywords": ["tor", "proxy"], "text": "..."},
]


def _registry() -> ToolRegistry:
    return ToolRegistry(threat_intel=FEED, asset_inventory=INVENTORY, user_baselines=BASELINES, attack_techniques=TECHNIQUES)


def test_agent_investigates_malicious_incident_end_to_end():
    incident = Incident(
        incident_id="INC-1",
        hostname="FIN-SQL01",
        user="asingh",
        process_name="powershell.exe",
        command_line="powershell.exe -enc SQBuAHYAbwBrAGUA",
        indicators=["185.220.101.7"],
        description="Encoded PowerShell beaconing to a known C2 IP.",
    )
    agent = InvestigationAgent(tools=_registry())
    report = agent.investigate(incident)

    assert report.severity == "critical"
    assert report.llm_backed_planning is False
    assert report.llm_backed_narrative is False
    tool_names = [s.call.tool for s in report.steps]
    assert "threat_intel_lookup" in tool_names
    assert "process_reputation_lookup" in tool_names
    assert "attack_technique_lookup" in tool_names
    assert any("isolate" in a.lower() for a in report.recommended_actions)
    assert "offline heuristic narrative" in report.narrative


def test_agent_finishes_early_on_benign_incident():
    incident = Incident(
        incident_id="INC-2",
        hostname="WKS-0231",
        user="jsmith",
        process_name="outlook.exe",
        command_line="outlook.exe",
        indicators=[],
        description="Routine login, low-priority rule.",
    )
    agent = InvestigationAgent(tools=_registry())
    report = agent.investigate(incident)

    assert report.severity == "low"
    tool_names = [s.call.tool for s in report.steps]
    # No indicators/process/deviation found suspicious -> ATT&CK lookup skipped entirely.
    assert "attack_technique_lookup" not in tool_names
    assert len(report.steps) < agent.max_steps


def test_score_verdict_with_no_evidence_is_low():
    state = AgentState(incident=Incident(incident_id="INC-3"))
    severity, actions = score_verdict(state)
    assert severity == "low"
    assert "monitor" in actions[0].lower()


def test_score_verdict_high_confidence_hit_on_critical_asset_is_critical():
    state = AgentState(incident=Incident(incident_id="INC-4"))
    state.steps.append(
        ToolStep(
            call=ToolCall("threat_intel_lookup", {"indicator": "1.2.3.4"}),
            result={"indicator": "1.2.3.4", "is_malicious": True, "confidence": "high"},
        )
    )
    state.steps.append(
        ToolStep(call=ToolCall("asset_criticality_lookup", {"hostname": "DC01"}), result={"criticality": "critical"})
    )
    severity, _ = score_verdict(state)
    assert severity == "critical"
