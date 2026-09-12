"""Render a ScanReport as JSON or Markdown."""

from __future__ import annotations

import json

from .findings import SEVERITY_ORDER
from .scanner import ScanReport

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def to_json(report: ScanReport) -> str:
    return json.dumps(report.as_dict(), indent=2)


def to_markdown(report: ScanReport) -> str:
    emoji = _SEVERITY_EMOJI.get(report.risk.overall_severity, "")
    lines = [
        f"# Attack Surface Report: {report.target}",
        "",
        f"**Scanned at:** {report.scanned_at}",
        f"**Overall risk:** {emoji} {report.risk.overall_severity.upper()} "
        f"(score {report.risk.score}/100)",
        f"**LLM-backed summary:** {'yes' if report.llm_backed else 'no (offline heuristic fallback)'}",
        "",
    ]

    if report.errors:
        lines.append("## Errors")
        lines += [f"- {e}" for e in report.errors]
        lines.append("")

    if report.summary:
        lines += ["## Executive summary", report.summary, ""]

    lines.append("## Findings")
    if not report.findings:
        lines.append("No findings were raised by any check.")
    else:
        ordered = sorted(
            report.findings, key=lambda f: SEVERITY_ORDER.index(f.severity), reverse=True
        )
        for f in ordered:
            sev_emoji = _SEVERITY_EMOJI.get(f.severity, "")
            lines.append(f"### {sev_emoji} [{f.severity.upper()}] {f.title}")
            lines.append(f"- **Category:** {f.category}")
            lines.append(f"- **Detail:** {f.detail}")
            lines.append(f"- **Recommendation:** {f.recommendation}")
            lines.append("")

    return "\n".join(lines)


def render(report: ScanReport, fmt: str = "markdown") -> str:
    if fmt == "json":
        return to_json(report)
    if fmt in ("markdown", "md"):
        return to_markdown(report)
    raise ValueError(f"unknown report format: {fmt!r}")
