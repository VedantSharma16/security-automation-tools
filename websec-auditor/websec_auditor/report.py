"""Render an AuditResult as JSON or a readable Markdown report."""

from __future__ import annotations

import json

from .audit import AuditResult
from .findings import SEVERITY_ORDER

_SEVERITY_ICON = {
    "critical": "[CRIT]",
    "high": "[HIGH]",
    "medium": "[MED] ",
    "low": "[LOW] ",
    "info": "[INFO]",
}


def render_json(result: AuditResult, *, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent)


def render_markdown(result: AuditResult) -> str:
    lines = [
        f"# Web Security Audit: {result.url}",
        "",
        f"**Final URL:** {result.final_url}  ",
        f"**HTTP status:** {result.status}  ",
        f"**Grade:** {result.grade} ({result.score}/100)",
        "",
    ]

    if result.fetch_error:
        lines.append(f"> Fetch failed: {result.fetch_error}")
        return "\n".join(lines) + "\n"

    if result.technologies:
        lines.append("## Fingerprint")
        lines.extend(f"- {tech}" for tech in result.technologies)
        lines.append("")

    if result.well_known:
        lines.append("## Well-known paths")
        for path, status in result.well_known.items():
            lines.append(f"- `/{path}` -> HTTP {status}")
        lines.append("")

    lines.append("## Findings")
    if not result.findings:
        lines.append("No issues found.")
    else:
        ordered = sorted(
            result.findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity),
            reverse=True,
        )
        for finding in ordered:
            icon = _SEVERITY_ICON.get(finding.severity, finding.severity.upper())
            lines.append(f"- {icon} **{finding.category}** — {finding.message}")
            if finding.recommendation:
                lines.append(f"    - Recommendation: {finding.recommendation}")
    lines.append("")

    return "\n".join(lines)
