"""The ReAct-style agent loop: plan -> act -> observe -> repeat -> finish."""

from __future__ import annotations

from dataclasses import dataclass

from .planner import AgentAction, Finish
from .tools import ToolResult


@dataclass
class TranscriptStep:
    index: int
    action: AgentAction
    result: ToolResult


@dataclass
class AgentRun:
    target: str
    steps: list[TranscriptStep]
    finished_reason: str
    planner_name: str


def run_agent(target: str, toolbox, planner, max_steps: int = 8) -> AgentRun:
    """Drive ``planner`` against ``toolbox`` until it finishes or the step budget runs out."""
    steps: list[TranscriptStep] = []
    finished_reason = "Reached max step budget."

    for index in range(max_steps):
        decision = planner.plan(index, steps)
        if isinstance(decision, Finish):
            finished_reason = decision.thought
            break

        method = getattr(toolbox, decision.tool, None)
        if method is None:
            result = ToolResult(decision.tool, False, {}, error=f"Unknown tool '{decision.tool}'.")
        else:
            try:
                result = method(**decision.kwargs)
            except TypeError as exc:
                result = ToolResult(decision.tool, False, {}, error=f"Invalid arguments for {decision.tool}: {exc}")

        steps.append(TranscriptStep(index, decision, result))

    return AgentRun(target, steps, finished_reason, planner.__class__.__name__)
