"""Data structures shared by the planner, the LLM agent, and the report renderer."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Alert:
    """A normalized security alert handed to the investigation loop."""

    alert_id: str
    description: str
    indicators: list[str] = field(default_factory=list)
    host: str | None = None
    raw: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        return cls(
            alert_id=data.get("alert_id", "unknown"),
            description=data.get("description", ""),
            indicators=list(data.get("indicators", [])),
            host=data.get("host"),
            raw=data.get("raw", data.get("description", "")),
        )

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "description": self.description,
            "indicators": self.indicators,
            "host": self.host,
            "raw": self.raw,
        }


@dataclass
class ToolCall:
    """One step of the investigation trace: a tool invocation and its outcome."""

    tool: str
    input: dict
    output: dict
    reasoning: str

    def to_dict(self) -> dict:
        return {"tool": self.tool, "input": self.input, "output": self.output, "reasoning": self.reasoning}


@dataclass
class InvestigationResult:
    """The final output of an investigation: verdict, evidence trail, and next steps."""

    alert: Alert
    trace: list[ToolCall]
    risk_score: int
    risk_band: str
    verdict: str
    confidence: str
    summary: str
    recommended_actions: list[str]
    mode: str

    def to_dict(self) -> dict:
        return {
            "alert": self.alert.to_dict(),
            "trace": [step.to_dict() for step in self.trace],
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "summary": self.summary,
            "recommended_actions": self.recommended_actions,
            "mode": self.mode,
        }
