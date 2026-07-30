"""Shared data model: severities and findings produced by every scan module."""

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


@dataclass(frozen=True)
class Finding:
    """A single reconnaissance/exposure finding."""

    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str = ""
    remediation: str = ""
    owasp_ref: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.name,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "owasp_ref": self.owasp_ref,
        }


@dataclass
class ScanResult:
    """Aggregate result of a full scan against one target."""

    target: str
    started_at: str
    finished_at: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
        }
