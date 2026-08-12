"""Typed data structures shared by the planner, agent loop, and CLI."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Alert:
    """A single security alert handed to the agent for investigation."""

    alert_id: str
    title: str
    description: str
    source_ip: str | None = None
    destination: str | None = None
    user: str | None = None
    hostname: str | None = None
    raw_indicators: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "destination": self.destination,
            "user": self.user,
            "hostname": self.hostname,
            "raw_indicators": self.raw_indicators,
        }


@dataclass
class AgentStep:
    """One tool call the agent made, and what it learned from it."""

    step: int
    tool: str
    input: dict
    output: dict | None

    def to_dict(self) -> dict:
        return {"step": self.step, "tool": self.tool, "input": self.input, "output": self.output}


@dataclass
class Verdict:
    """The agent's final call on an alert."""

    verdict: str  # "malicious" | "suspicious" | "benign" | "inconclusive"
    confidence: float
    recommended_action: str
    rationale: str

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "recommended_action": self.recommended_action,
            "rationale": self.rationale,
        }


@dataclass
class AgentResult:
    """Full output of an investigation: the reasoning trace plus the verdict."""

    alert: Alert
    trace: list[AgentStep]
    verdict: Verdict
    mode: str  # "live" | "offline" | "live-max-steps"

    def to_dict(self) -> dict:
        return {
            "alert": self.alert.to_dict(),
            "mode": self.mode,
            "trace": [step.to_dict() for step in self.trace],
            "verdict": self.verdict.to_dict(),
        }
