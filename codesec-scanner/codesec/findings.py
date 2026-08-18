"""Shared data model for scanner findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so that comparisons like ``severity >= Severity.HIGH`` work."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name for s in cls)
            raise ValueError(f"Unknown severity {name!r}. Valid values: {valid}") from exc


@dataclass(frozen=True)
class Finding:
    """A single security finding produced by a detector."""

    rule_id: str
    title: str
    severity: Severity
    cwe: str
    file: str
    line: int
    snippet: str
    description: str
    remediation: str
    column: int = 0

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "cwe": self.cwe,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "description": self.description,
            "remediation": self.remediation,
        }


@dataclass
class ScanResult:
    """All findings produced for a scan target, plus bookkeeping metadata."""

    findings: list = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> list:
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.file, f.line))

    def count_by_severity(self) -> dict:
        counts = {s.name: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.name] += 1
        return counts

    def max_severity(self):
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)
