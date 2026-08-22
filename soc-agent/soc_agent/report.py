"""Human-readable rendering of an :class:`InvestigationReport`."""

from __future__ import annotations

from soc_agent.agent import InvestigationReport

_SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


def render_human(report: InvestigationReport) -> str:
    icon = _SEVERITY_ICONS.get(report.severity, "")
    lines = [
        f"{icon} Severity: {report.severity.upper()}",
        f"Incident: {report.incident.incident_id}",
        f"Planning: {'LLM tool-use' if report.llm_backed_planning else 'deterministic (offline)'}",
        f"Narrative: {'LLM-generated' if report.llm_backed_narrative else 'offline heuristic fallback'}",
        "",
        f"Investigation steps ({len(report.steps)}):",
    ]
    if report.steps:
        for step in report.steps:
            lines.append(f"  - {step.call.tool}({step.call.arguments})")
            lines.append(f"      -> {step.result}")
    else:
        lines.append("  (agent finished without calling any tools)")

    lines.append("")
    lines.append("Recommended actions:")
    for action in report.recommended_actions:
        lines.append(f"  - {action}")

    lines.append("")
    lines.append("Narrative:")
    lines.append(report.narrative)
    return "\n".join(lines)
