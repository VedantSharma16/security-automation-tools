"""Data structures shared by the planner, LLM agent, and reporting layers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Alert:
    """A single SOC alert pulled from an upstream detection source (EDR, IDS, IAM, ...)."""

    alert_id: str
    timestamp: str
    source: str
    host: str
    description: str
    user: str | None = None
    src_ip: str | None = None
    raw_indicators: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        return cls(
            alert_id=data["alert_id"],
            timestamp=data["timestamp"],
            source=data["source"],
            host=data["host"],
            description=data["description"],
            user=data.get("user"),
            src_ip=data.get("src_ip"),
            raw_indicators=data.get("raw_indicators", {}),
        )

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "description": self.description,
            "raw_indicators": self.raw_indicators,
        }


@dataclass
class AgentStep:
    """One tool invocation the agent made, plus its result, in order."""

    step_number: int
    tool_name: str
    tool_args: dict
    tool_result: dict
    thought: str | None = None

    def to_dict(self) -> dict:
        return {
            "step_number": self.step_number,
            "thought": self.thought,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "tool_result": self.tool_result,
        }


@dataclass
class AgentResult:
    """The agent's final output for one alert: verdict, rationale, and full audit trail."""

    alert_id: str
    verdict: str  # "escalate" | "monitor" | "close"
    reason: str
    steps: list[AgentStep]
    backend: str  # "llm" | "deterministic"
    note: str | None = None

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "verdict": self.verdict,
            "reason": self.reason,
            "backend": self.backend,
            "note": self.note,
            "steps": [s.to_dict() for s in self.steps],
        }
