"""Shared finding model used across all checkers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    recommendation: str
    evidence: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.name,
            "category": self.category,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "references": self.references,
        }
