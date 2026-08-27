"""Aggregates scan findings into a severity-scored, renderable report."""

from __future__ import annotations

import json
from dataclasses import dataclass

from llm_redteam.attacks import CATEGORY_NAMES
from llm_redteam.scanner import ScanFinding

SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


@dataclass
class ScanReport:
    target_name: str
    total_attacks: int
    vulnerable_count: int
    severity: str
    findings: list[ScanFinding]

    def to_dict(self) -> dict:
        return {
            "target": self.target_name,
            "total_attacks": self.total_attacks,
            "vulnerable_count": self.vulnerable_count,
            "severity": self.severity,
            "findings": [
                {
                    "attack_id": f.attack.id,
                    "attack_name": f.attack.name,
                    "category": f.attack.category,
                    "category_name": f.attack.category_name,
                    "technique": f.attack.technique,
                    "vulnerable": f.verdict.vulnerable,
                    "confidence": f.verdict.confidence,
                    "basis": f.verdict.basis,
                    "evidence": f.verdict.evidence,
                }
                for f in self.findings
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def compute_severity(findings: list[ScanFinding]) -> str:
    vulnerable = [f for f in findings if f.verdict.vulnerable]
    if any(f.verdict.basis == "secret_leak" for f in vulnerable):
        return "critical"
    if len(vulnerable) >= 3:
        return "high"
    if len(vulnerable) >= 1:
        return "medium"
    return "low"


def build_report(target_name: str, findings: list[ScanFinding]) -> ScanReport:
    vulnerable = [f for f in findings if f.verdict.vulnerable]
    return ScanReport(
        target_name=target_name,
        total_attacks=len(findings),
        vulnerable_count=len(vulnerable),
        severity=compute_severity(findings),
        findings=findings,
    )


def render_text(report: ScanReport) -> str:
    lines = []
    emoji = SEVERITY_EMOJI.get(report.severity, "")
    lines.append(f"{emoji} Overall risk: {report.severity.upper()}")
    lines.append(f"Target: {report.target_name}")
    lines.append(f"Attacks run: {report.total_attacks}  |  Vulnerable: {report.vulnerable_count}")
    lines.append("")

    by_category: dict[str, list[ScanFinding]] = {}
    for finding in report.findings:
        by_category.setdefault(finding.attack.category, []).append(finding)

    for category, cat_findings in by_category.items():
        cat_vulnerable = [f for f in cat_findings if f.verdict.vulnerable]
        name = CATEGORY_NAMES.get(category, category)
        lines.append(f"## {category} — {name} ({len(cat_vulnerable)}/{len(cat_findings)} vulnerable)")
        for finding in cat_findings:
            mark = "❌ VULNERABLE" if finding.verdict.vulnerable else "✅ safe"
            lines.append(
                f"  [{mark}] {finding.attack.id} — {finding.attack.name} "
                f"(confidence={finding.verdict.confidence:.2f}, basis={finding.verdict.basis})"
            )
            if finding.verdict.vulnerable:
                lines.append(f"      evidence: {finding.verdict.evidence!r}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
