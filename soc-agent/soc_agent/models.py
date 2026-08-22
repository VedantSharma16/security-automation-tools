"""Data model for an incoming incident and the agent's tool-call transcript."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Incident:
    incident_id: str
    hostname: str | None = None
    user: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    indicators: list[str] = field(default_factory=list)
    description: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Incident":
        return cls(
            incident_id=data.get("incident_id", "UNKNOWN"),
            hostname=data.get("hostname"),
            user=data.get("user"),
            process_name=data.get("process_name"),
            command_line=data.get("command_line"),
            indicators=list(data.get("indicators", [])),
            description=data.get("description", ""),
        )

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "hostname": self.hostname,
            "user": self.user,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "indicators": self.indicators,
            "description": self.description,
        }


@dataclass
class ToolCall:
    tool: str
    arguments: dict = field(default_factory=dict)


@dataclass
class ToolStep:
    call: ToolCall
    result: dict

    def to_dict(self) -> dict:
        return {"tool": self.call.tool, "arguments": self.call.arguments, "result": self.result}
