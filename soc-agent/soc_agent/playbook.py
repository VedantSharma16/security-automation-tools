"""Data model shared by the investigative tools, the agent, and the report renderer."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AlertCase:
    """A normalized security alert. Only ``alert_id`` and ``description`` are required —
    every other field is optional so the agent only investigates what's actually present.
    """

    alert_id: str
    description: str
    timestamp: str | None = None
    hostname: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    username: str | None = None
    process_name: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AlertCase":
        return cls(
            alert_id=data["alert_id"],
            description=data.get("description", ""),
            timestamp=data.get("timestamp"),
            hostname=data.get("hostname"),
            source_ip=data.get("source_ip"),
            dest_ip=data.get("dest_ip"),
            username=data.get("username"),
            process_name=data.get("process_name"),
        )


@dataclass
class ToolCallRecord:
    """One step in the agent's investigation trace: a tool call and its result."""

    tool: str
    arguments: dict
    result: dict


@dataclass
class IncidentReport:
    alert: AlertCase
    trace: list[ToolCallRecord] = field(default_factory=list)
    verdict: str = "benign"
    confidence: str = "low"
    score: int = 0
    evidence: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    mode: str = "offline"
    warnings: list[str] = field(default_factory=list)
