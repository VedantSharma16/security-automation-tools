"""The agentic investigation loop.

This is a small ReAct-style loop: at each turn a *planner* looks at the
alert and everything observed so far, and decides either to call one more
tool or to conclude the investigation. The loop itself doesn't care whether
the planner is a live LLM or a scripted stand-in — both implement the same
:class:`Planner` protocol, so the control flow, transcript bookkeeping, and
stopping conditions are exercised identically either way.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from .environment import Environment
from .tools import ToolError, execute_tool

DEFAULT_MAX_TURNS = 8


@dataclass
class ToolCallStep:
    """A planner decision to call one more tool before concluding."""

    name: str
    arguments: dict
    reasoning: str = ""


@dataclass
class FinalStep:
    """A planner decision that enough evidence has been gathered to conclude."""

    verdict: str  # "malicious" | "benign" | "inconclusive"
    severity: str  # "critical" | "high" | "medium" | "low" | "informational"
    summary: str


@dataclass
class Turn:
    """One completed step of the investigation, tool call or final."""

    step_number: int
    reasoning: str
    action: str  # "tool_call" | "final"
    name: str | None = None
    arguments: dict = field(default_factory=dict)
    observation: dict | None = None
    error: str | None = None


class Planner(Protocol):
    def next_step(self, alert: dict, transcript: list[Turn]) -> ToolCallStep | FinalStep: ...


@dataclass
class InvestigationReport:
    alert: dict
    transcript: list[Turn]
    verdict: str
    severity: str
    summary: str
    truncated: bool = False


def investigate(
    alert: dict,
    environment: Environment,
    planner: Planner,
    max_turns: int = DEFAULT_MAX_TURNS,
) -> InvestigationReport:
    """Drive the agent loop to completion (or until ``max_turns`` is hit)."""
    transcript: list[Turn] = []

    for step_number in range(1, max_turns + 1):
        step = planner.next_step(alert, transcript)

        if isinstance(step, FinalStep):
            transcript.append(
                Turn(step_number=step_number, reasoning=step.summary, action="final")
            )
            return InvestigationReport(
                alert=alert,
                transcript=transcript,
                verdict=step.verdict,
                severity=step.severity,
                summary=step.summary,
            )

        try:
            observation = execute_tool(step.name, step.arguments, environment)
            error = None
        except ToolError as exc:
            observation = None
            error = str(exc)

        transcript.append(
            Turn(
                step_number=step_number,
                reasoning=step.reasoning,
                action="tool_call",
                name=step.name,
                arguments=step.arguments,
                observation=observation,
                error=error,
            )
        )

    return InvestigationReport(
        alert=alert,
        transcript=transcript,
        verdict="inconclusive",
        severity="unknown",
        summary=(
            f"Investigation did not reach a conclusion within {max_turns} turns. "
            "Escalate to a human analyst for manual review."
        ),
        truncated=True,
    )
