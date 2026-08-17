"""Render a ReconReport as human-readable console output."""

from __future__ import annotations

from recon_agent.agent import ReconReport

_SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "🟢",
}


def render_human(report: ReconReport) -> str:
    icon = _SEVERITY_ICONS.get(report.severity, "")
    lines = [
        f"{icon} Target: {report.target}  —  Severity: {report.severity.upper()}",
        f"Mode: {'agentic (LLM tool-use loop)' if report.agent_backed else 'offline deterministic pipeline'}"
        f", {report.steps_taken} step(s)",
        "",
        f"Findings ({len(report.findings)}):",
    ]
    if report.findings:
        for finding in report.findings:
            lines.append(f"  - [{finding.severity}] {finding.category}: {finding.description}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Tools called:")
    for name, results in report.tool_results.items():
        lines.append(f"  - {name} x{len(results)}")

    lines.append("")
    lines.append("Summary:")
    lines.append(report.narrative)
    return "\n".join(lines)
