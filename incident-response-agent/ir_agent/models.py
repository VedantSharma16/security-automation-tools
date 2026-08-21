"""Shared data structures for the agent loop, tools, and final verdict."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolResult:
    """The observation produced by a single tool call."""

    tool: str
    tool_input: str
    malicious: bool
    summary: str
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "input": self.tool_input,
            "malicious": self.malicious,
            "summary": self.summary,
            "detail": self.detail,
        }


@dataclass
class AgentStep:
    """One iteration of the agent loop: a reasoning note, an action, and its observation."""

    step: int
    thought: str
    tool: str
    tool_input: str
    observation: ToolResult | None

    def to_dict(self) -> dict:
        return {
            "step": self.step,
            "thought": self.thought,
            "tool": self.tool,
            "tool_input": self.tool_input,
            "observation": self.observation.to_dict() if self.observation else None,
        }


@dataclass
class IncidentVerdict:
    """The agent's final, structured output for an incident."""

    severity: str
    confidence: float
    summary: str
    recommended_actions: list[str]
    evidence: list[ToolResult]
    trace: list[AgentStep]
    llm_backed: bool

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "summary": self.summary,
            "recommended_actions": self.recommended_actions,
            "evidence": [e.to_dict() for e in self.evidence],
            "trace": [s.to_dict() for s in self.trace],
            "llm_backed": self.llm_backed,
        }
