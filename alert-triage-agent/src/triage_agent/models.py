"""Core data types shared across the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so findings can be sorted worst-first."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class LogEvent:
    """A single normalized line of input, kept for traceability."""

    line_number: int
    raw: str
    source: str


@dataclass(frozen=True)
class Rule:
    """A single detection rule loaded from the rules file."""

    id: str
    name: str
    pattern: str
    severity: Severity
    mitre_technique: str
    description: str = ""


@dataclass(frozen=True)
class Finding:
    """A rule match against a specific log event."""

    rule: Rule
    event: LogEvent

    @property
    def severity(self) -> Severity:
        return self.rule.severity


@dataclass
class TriageReport:
    """The final artifact handed back to the user."""

    findings: list[Finding]
    summary: str
    generated_by: str
    stats: dict[str, int] = field(default_factory=dict)
