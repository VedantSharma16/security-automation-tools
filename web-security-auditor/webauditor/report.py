"""Assemble and render the final audit report."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from . import scoring

if TYPE_CHECKING:
    from .findings import Finding

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def build_report(target: str, findings: list[Finding], generated_at: str) -> dict:
    """Combine findings from every checker into a single JSON-serializable report."""
    ordered = sorted(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.name))
    return {
        "target": target,
        "generated_at": generated_at,
        "summary": scoring.build_summary(findings),
        "findings": [f.to_dict() for f in ordered],
    }


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def render_console(report: dict) -> str:
    """Render a human-readable console report."""
    summary = report["summary"]
    lines = [
        "=" * 70,
        f"Web Security Audit Report - {report['target']}",
        f"Generated: {report['generated_at']}",
        "=" * 70,
        "",
        f"Risk score:   {summary['risk_score']}/100  ({summary['risk_rating']})",
        f"Total findings: {summary['total_findings']}",
        "  " + "  ".join(f"{sev}={summary['by_severity'][sev]}" for sev in _SEVERITY_ORDER),
        "",
    ]

    if not report["findings"]:
        lines.append("No issues detected by the checks in this tool.")
    else:
        lines.append("-" * 70)
        for finding in report["findings"]:
            lines.append(f"[{finding['severity']}] {finding['title']}  ({finding['id']})")
            lines.append(f"    Category:       {finding['category']}")
            lines.append(f"    Description:    {finding['description']}")
            lines.append(f"    Recommendation: {finding['recommendation']}")
            if finding["evidence"]:
                lines.append(f"    Evidence:       {finding['evidence']}")
            lines.append("-" * 70)

    return "\n".join(lines)
