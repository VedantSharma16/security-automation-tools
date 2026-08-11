"""Shared mutable state threaded through a single investigation's agent loop."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolCallRecord:
    tool: str
    arguments: dict
    ok: bool
    output: dict


@dataclass
class InvestigationState:
    query: str
    trace: list[ToolCallRecord] = field(default_factory=list)

    def called(self, tool_name: str) -> bool:
        return any(record.tool == tool_name for record in self.trace)

    def results_for(self, tool_name: str) -> list[dict]:
        return [record.output for record in self.trace if record.tool == tool_name and record.ok]

    def arguments_for(self, tool_name: str, key: str) -> set[str]:
        return {
            record.arguments.get(key)
            for record in self.trace
            if record.tool == tool_name and key in record.arguments
        }
