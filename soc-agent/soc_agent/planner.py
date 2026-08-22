"""Planners decide which tool the agent calls next, given the state so far.

This is the piece that makes ``soc-agent`` an *agent* rather than a fixed
pipeline: the next action is chosen conditionally, at runtime, from the
incident plus whatever evidence prior tool calls have already surfaced —
including deciding there's nothing more useful to check and finishing early.

``DeterministicPlanner`` encodes that decision policy directly in Python and
needs no LLM, so the tool is fully runnable and testable offline. ``LLMPlanner``
swaps the policy for a real Claude tool-use call each step, falling back to
the deterministic policy if no API key/SDK is available or the call fails —
the agent loop in :mod:`soc_agent.agent` is identical either way.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from soc_agent.models import Incident, ToolCall, ToolStep

FINISH = "finish"


@dataclass
class AgentState:
    incident: Incident
    steps: list[ToolStep] = field(default_factory=list)

    def called(self, tool_name: str) -> bool:
        return any(step.call.tool == tool_name for step in self.steps)

    def results_for(self, tool_name: str) -> list[dict]:
        return [step.result for step in self.steps if step.call.tool == tool_name]


class DeterministicPlanner:
    """Fixed, but conditional, tool-selection policy. The offline default."""

    name = "deterministic"
    is_live = False

    def decide(self, state: AgentState) -> ToolCall:
        incident = state.incident
        already_checked = {r["indicator"] for r in state.results_for("threat_intel_lookup")}

        for indicator in incident.indicators:
            if indicator not in already_checked:
                return ToolCall("threat_intel_lookup", {"indicator": indicator})

        if (incident.process_name or incident.command_line) and not state.called("process_reputation_lookup"):
            return ToolCall(
                "process_reputation_lookup",
                {"process_name": incident.process_name, "command_line": incident.command_line},
            )

        if incident.hostname and not state.called("asset_criticality_lookup"):
            return ToolCall("asset_criticality_lookup", {"hostname": incident.hostname})

        if incident.user and not state.called("user_baseline_check"):
            return ToolCall("user_baseline_check", {"user": incident.user, "hostname": incident.hostname})

        if not state.called("attack_technique_lookup"):
            if self._has_suspicious_findings(state):
                return ToolCall("attack_technique_lookup", {"keywords": self._collect_keywords(state)})
            # Every mandatory check came back clean — an ATT&CK lookup would
            # just be busywork, so skip it and finish instead.
            return ToolCall(FINISH)

        return ToolCall(FINISH)

    @staticmethod
    def _has_suspicious_findings(state: AgentState) -> bool:
        return any(
            step.result.get("is_malicious") or step.result.get("is_suspicious") or step.result.get("is_deviation")
            for step in state.steps
        )

    @staticmethod
    def _collect_keywords(state: AgentState) -> list[str]:
        keywords: list[str] = []
        if state.incident.process_name:
            keywords.append(state.incident.process_name)
        if state.incident.description:
            keywords.append(state.incident.description)
        for step in state.steps:
            if step.call.tool == "process_reputation_lookup":
                keywords.extend(step.result.get("matched_patterns", []))
            if step.call.tool == "user_baseline_check" and step.result.get("is_deviation"):
                keywords.append("unusual login baseline deviation")
            if step.call.tool == "threat_intel_lookup" and step.result.get("is_malicious"):
                keywords.append("command and control beacon proxy tor")
        return keywords


class LLMPlanner:
    """Delegates tool selection to Claude via real tool-use, one step at a time."""

    name = "llm"

    def __init__(self, registry, llm_client=None):
        from soc_agent.llm_client import LLMClient  # local import avoids a cycle

        self.registry = registry
        self.llm_client = llm_client or LLMClient()
        self._fallback = DeterministicPlanner()

    @property
    def is_live(self) -> bool:
        return self.llm_client.is_live

    def decide(self, state: AgentState) -> ToolCall:
        decision = self.llm_client.plan_next(state, self.registry.specs())
        if decision is None:
            return self._fallback.decide(state)
        if decision["tool"] == "finish_investigation":
            return ToolCall(FINISH)
        return ToolCall(decision["tool"], decision.get("arguments", {}))
