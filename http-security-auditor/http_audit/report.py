"""Shared report data model: findings and the overall audit report."""

from __future__ import annotations

from dataclasses import dataclass, field

# Ordered worst-to-best; used for sorting and for scoring weights.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "pass"]


@dataclass
class Finding:
    category: str  # "headers" | "cookies" | "cors" | "tls" | "exposure"
    name: str
    severity: str  # one of SEVERITY_ORDER
    message: str
    recommendation: str | None = None

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "name": self.name,
            "severity": self.severity,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class AuditReport:
    url: str
    status_code: int
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    llm_backed: bool = False
    summary: str = ""

    def findings_by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else len(SEVERITY_ORDER),
        )

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "score": self.score,
            "grade": self.grade,
            "llm_backed": self.llm_backed,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

    def to_markdown(self) -> str:
        lines = [
            f"# HTTP Security Audit — {self.url}",
            "",
            f"**Grade:** {self.grade}  **Score:** {self.score}/100  "
            f"**HTTP status:** {self.status_code}",
            "",
            "## Findings",
            "",
        ]
        for f in self.sorted_findings():
            lines.append(f"- **[{f.severity.upper()}]** ({f.category}) {f.name}: {f.message}")
            if f.recommendation:
                lines.append(f"  - _Recommendation:_ {f.recommendation}")
        lines += ["", "## Summary", "", self.summary]
        return "\n".join(lines)
