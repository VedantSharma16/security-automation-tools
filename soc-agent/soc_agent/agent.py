"""The investigation loop: plan -> act -> observe -> replan, until finished.

This is deliberately a small, from-scratch ReAct-style loop (no agent
framework) so the control flow is fully inspectable: :class:`InvestigationAgent`
repeatedly asks its planner for the next tool call, executes it, appends the
observation to the running state, and stops either when the planner decides
to finish or a hard ``max_steps`` safety cap is hit.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from soc_agent.llm_client import LLMClient
from soc_agent.models import Incident, ToolStep
from soc_agent.planner import FINISH, AgentState, DeterministicPlanner
from soc_agent.tools import ToolRegistry

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


@dataclass
class InvestigationReport:
    incident: Incident
    steps: list[ToolStep]
    severity: str
    recommended_actions: list[str]
    narrative: str
    llm_backed_planning: bool
    llm_backed_narrative: bool
    hit_step_limit: bool = False

    def to_dict(self) -> dict:
        return {
            "incident": self.incident.to_dict(),
            "steps": [s.to_dict() for s in self.steps],
            "severity": self.severity,
            "recommended_actions": self.recommended_actions,
            "narrative": self.narrative,
            "llm_backed_planning": self.llm_backed_planning,
            "llm_backed_narrative": self.llm_backed_narrative,
            "hit_step_limit": self.hit_step_limit,
        }


def score_verdict(state: AgentState) -> tuple[str, list[str]]:
    """Deterministic severity scoring and action recommendation from the
    gathered evidence. Kept separate from tool selection so the verdict is
    reproducible regardless of which planner drove the investigation."""
    malicious_hits = [s.result for s in state.steps if s.call.tool == "threat_intel_lookup" and s.result.get("is_malicious")]
    suspicious_process = any(
        s.result.get("is_suspicious") for s in state.steps if s.call.tool == "process_reputation_lookup"
    )
    deviation = any(s.result.get("is_deviation") for s in state.steps if s.call.tool == "user_baseline_check")
    critical_asset = any(
        s.result.get("criticality") in {"critical", "high"} for s in state.steps if s.call.tool == "asset_criticality_lookup"
    )
    high_impact_technique = any(
        t.get("tactic") in {"Impact", "Credential Access", "Command and Control"}
        for s in state.steps
        if s.call.tool == "attack_technique_lookup"
        for t in s.result.get("matches", [])
    )

    actions: list[str] = []
    if malicious_hits or suspicious_process:
        actions.append("Isolate the affected host from the network pending further investigation")
    if malicious_hits:
        actions.append("Block the flagged indicators at the firewall/EDR and hunt for them elsewhere in the environment")
    if suspicious_process:
        actions.append("Collect a memory/process forensic snapshot before remediating")
    if deviation:
        actions.append("Verify the login with the account owner and consider forcing a credential reset")
    if not actions:
        actions.append("No corroborating evidence found; monitor and close if no further activity is observed")

    high_confidence_malicious = any(r.get("confidence") == "high" for r in malicious_hits)

    if high_confidence_malicious and critical_asset:
        return SEVERITY_CRITICAL, actions
    if malicious_hits or (suspicious_process and deviation):
        return SEVERITY_HIGH, actions
    if suspicious_process or deviation or high_impact_technique:
        return SEVERITY_MEDIUM, actions
    return SEVERITY_LOW, actions


class InvestigationAgent:
    def __init__(self, tools: ToolRegistry | None = None, planner=None, llm_client: LLMClient | None = None, max_steps: int = 8):
        self.tools = tools or ToolRegistry()
        self.planner = planner or DeterministicPlanner()
        self.llm_client = llm_client or LLMClient()
        self.max_steps = max_steps

    def investigate(self, incident: Incident) -> InvestigationReport:
        state = AgentState(incident=incident)
        hit_step_limit = True

        for _ in range(self.max_steps):
            action = self.planner.decide(state)
            if action.tool == FINISH:
                hit_step_limit = False
                break
            result = self.tools.call(action.tool, action.arguments)
            state.steps.append(ToolStep(call=action, result=result))

        severity, actions = score_verdict(state)
        narrative = self.llm_client.narrate(incident, state.steps, severity, actions)

        return InvestigationReport(
            incident=incident,
            steps=state.steps,
            severity=severity,
            recommended_actions=actions,
            narrative=narrative,
            llm_backed_planning=getattr(self.planner, "is_live", False),
            llm_backed_narrative=self.llm_client.is_live,
            hit_step_limit=hit_step_limit,
        )
