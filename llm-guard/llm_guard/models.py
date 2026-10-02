"""Shared data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str  # OWASP LLM Top 10 style label, e.g. "LLM01"
    severity: Severity
    description: str
    evidence: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.name,
            "description": self.description,
            "evidence": self.evidence,
        }


@dataclass
class Verdict:
    findings: list[Finding] = field(default_factory=list)
    score: int = 0  # 0-100
    blocked: bool = False
    sanitized: str | None = None

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "blocked": self.blocked,
            "findings": [f.to_dict() for f in self.findings],
        }
