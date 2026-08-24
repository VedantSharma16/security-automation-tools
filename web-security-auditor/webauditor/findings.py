"""Shared finding model used by every checker module."""

from __future__ import annotations

from dataclasses import dataclass
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
    owasp_category: str
    description: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.name,
            "owasp_category": self.owasp_category,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
