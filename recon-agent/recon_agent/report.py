"""Render a ReconReport as Markdown or JSON, with a deterministic offline
narrative fallback for when no LLM narrative was produced.
"""
from __future__ import annotations

import json

from .models import ReconReport

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def offline_narrative(report: ReconReport) -> str:
    findings = sorted(report.findings, key=lambda f: SEVERITY_ORDER[f.severity])
    if not findings:
        return (
            f"No security-relevant findings were surfaced for {report.target}. "
            f"Overall posture score: {report.score}/100 (grade {report.grade})."
        )

    counts: dict = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    counts_str = ", ".join(
        f"{n} {sev}" for sev, n in sorted(counts.items(), key=lambda kv: SEVERITY_ORDER[kv[0]])
    )
    top = findings[0]
    return (
        f"Recon of {report.target} surfaced {len(findings)} finding(s) ({counts_str}). "
        f"Overall posture score: {report.score}/100 (grade {report.grade}). "
        f"Highest-priority issue: '{top.title}' — {top.recommendation}"
    )


def to_markdown(report: ReconReport) -> str:
    lines = [
        f"# Recon Report: {report.target}",
        "",
        f"**Score:** {report.score}/100 (Grade {report.grade})",
        "",
        "## Summary",
        report.narrative or offline_narrative(report),
        "",
        "## Findings",
    ]

    findings = sorted(report.findings, key=lambda f: SEVERITY_ORDER[f.severity])
    if not findings:
        lines.append("No findings.")
    for finding in findings:
        lines.append(f"### [{SEVERITY_LABEL[finding.severity]}] {finding.title} ({finding.tool})")
        lines.append(finding.detail)
        lines.append(f"**Recommendation:** {finding.recommendation}")
        lines.append("")

    lines.append("## Raw Tool Data")
    for result in report.tool_results:
        lines.append(f"### {result.tool}")
        lines.append("```json")
        lines.append(json.dumps(result.data, indent=2, default=str))
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def to_json(report: ReconReport) -> str:
    payload = {
        "target": report.target,
        "score": report.score,
        "grade": report.grade,
        "narrative": report.narrative or offline_narrative(report),
        "findings": [
            {
                "tool": f.tool,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "recommendation": f.recommendation,
            }
            for f in sorted(report.findings, key=lambda f: SEVERITY_ORDER[f.severity])
        ],
        "tool_results": [{"tool": r.tool, "data": r.data} for r in report.tool_results],
    }
    return json.dumps(payload, indent=2, default=str)
