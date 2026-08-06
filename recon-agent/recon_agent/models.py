"""Shared data models for the recon agent pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    tool: str
    severity: str
    title: str
    detail: str
    recommendation: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"Unknown severity: {self.severity!r}")


@dataclass
class ToolResult:
    tool: str
    data: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)


@dataclass
class ReconReport:
    target: str
    tool_results: List[ToolResult] = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    narrative: str = ""

    @property
    def findings(self) -> List[Finding]:
        all_findings: List[Finding] = []
        for result in self.tool_results:
            all_findings.extend(result.findings)
        return all_findings
