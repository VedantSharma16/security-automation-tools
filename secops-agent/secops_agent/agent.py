"""The plan -> act -> observe orchestration loop, wired to a planner and tool registry."""

from __future__ import annotations

from dataclasses import dataclass

from .planner import Planner
from .state import InvestigationState, ToolCallRecord
from .tools import ToolRegistry

DEFAULT_MAX_ITERATIONS = 8


@dataclass
class Investigation:
    query: str
    trace: list[ToolCallRecord]
    final_report: str
    verdict: str
    stopped_early: bool


class SecOpsAgent:
    """Runs an investigation to completion or until the iteration budget is exhausted."""

    def __init__(self, planner: Planner, tools: ToolRegistry, max_iterations: int = DEFAULT_MAX_ITERATIONS):
        self.planner = planner
        self.tools = tools
        self.max_iterations = max_iterations

    def investigate(self, query: str) -> Investigation:
        state = InvestigationState(query=query)
        stopped_early = True
        final_report = ""

        for _ in range(self.max_iterations):
            action = self.planner.decide(state)

            if action.kind == "final":
                final_report = action.final_text or ""
                stopped_early = False
                break

            raw = self.tools.execute(action.tool_name, action.tool_args or {})
            output = raw["result"] if raw["ok"] else {"error": raw.get("error")}
            record = ToolCallRecord(tool=action.tool_name, arguments=action.tool_args or {}, ok=raw["ok"], output=output)
            state.trace.append(record)
            self.planner.observe(action, output)
        else:
            final_report = (
                f"Investigation stopped after reaching the {self.max_iterations}-tool-call budget "
                "without a final answer. Escalate to a human analyst with the trace below."
            )

        return Investigation(
            query=query,
            trace=state.trace,
            final_report=final_report,
            verdict=derive_verdict(state.trace),
            stopped_early=stopped_early,
        )


def derive_verdict(trace: list[ToolCallRecord]) -> str:
    malicious = any(
        record.tool == "lookup_ioc" and record.ok and record.output.get("is_known_malicious") for record in trace
    )
    critical_asset = any(
        record.tool == "check_asset_criticality"
        and record.ok
        and record.output.get("found")
        and record.output.get("criticality") in ("critical", "high")
        for record in trace
    )
    any_ioc_checked = any(record.tool == "lookup_ioc" and record.ok for record in trace)

    if malicious and critical_asset:
        return "malicious (critical asset in scope)"
    if malicious:
        return "malicious"
    if critical_asset:
        return "suspicious (critical asset in scope, no confirmed-malicious IOC)"
    if any_ioc_checked:
        return "inconclusive"
    return "no evidence gathered"
