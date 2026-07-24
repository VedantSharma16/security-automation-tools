"""Shared data model for scan findings."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    """A single detected secret."""

    rule_id: str
    description: str
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    file: str
    line: int
    redacted: str
    fingerprint: str
    commit: str | None = None  # set when found via git history scan, else None (working tree)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "redacted": self.redacted,
            "fingerprint": self.fingerprint,
            "commit": self.commit,
        }


@dataclass
class ScanResult:
    """The full output of a scan: every finding plus baseline bookkeeping."""

    findings: list[Finding] = field(default_factory=list)
    baselined_fingerprints: set[str] = field(default_factory=set)

    @property
    def new_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.fingerprint not in self.baselined_fingerprints]

    @property
    def baselined_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.fingerprint in self.baselined_fingerprints]
