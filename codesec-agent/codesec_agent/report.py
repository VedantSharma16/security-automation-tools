"""Rendering an :class:`~codesec_agent.agent.AgentReport` for humans or CI."""

from __future__ import annotations

import json
from pathlib import Path

from .agent import AgentReport
from .rules import SEVERITIES

_SEVERITY_ICONS = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡"}


def filter_by_min_severity(report: AgentReport, min_severity: str) -> AgentReport:
    if min_severity not in SEVERITIES:
        raise ValueError(f"unknown severity '{min_severity}'")
    threshold = SEVERITIES.index(min_severity)
    kept = [f for f in report.findings if SEVERITIES.index(f.severity) >= threshold]
    report.findings = kept
    for sev in SEVERITIES:
        if SEVERITIES.index(sev) < threshold:
            report.severity_counts[sev] = 0
    return report


def render_console(report: AgentReport) -> str:
    lines = [
        f"CodeSec Agent — scan of {report.root}",
        f"LLM-backed: {'yes' if report.llm_backed else 'no (offline heuristic fallback)'}",
        f"Files scanned: {len(report.files_scanned)}",
    ]
    if report.parse_errors:
        lines.append(f"Files skipped (parse errors): {len(report.parse_errors)}")

    counts = report.severity_counts
    lines.append(
        "Findings: "
        + ", ".join(f"{counts.get(sev, 0)} {sev}" for sev in ("critical", "high", "medium", "low"))
    )
    lines.append("")

    if report.findings:
        for f in report.findings:
            icon = _SEVERITY_ICONS.get(f.severity, "")
            lines.append(f"{icon} [{f.severity.upper()}] {f.file}:{f.line} — {f.title} ({f.cwe})")
            lines.append(f"    {f.snippet}")
            lines.append(f"    fix: {f.remediation}")
    else:
        lines.append("No findings at or above the selected severity threshold.")

    if report.tool_calls:
        lines.append("")
        lines.append(f"Agent tool calls ({len(report.tool_calls)}):")
        for call in report.tool_calls:
            lines.append(f"  - {call['name']}({call['input']})")

    lines.append("")
    lines.append("Review:")
    lines.append(report.narrative)
    return "\n".join(lines)


def render_markdown(report: AgentReport) -> str:
    counts = report.severity_counts
    lines = [
        f"# CodeSec Agent report — `{report.root}`",
        "",
        f"- **LLM-backed:** {'yes' if report.llm_backed else 'no (offline heuristic fallback)'}",
        f"- **Files scanned:** {len(report.files_scanned)}",
        f"- **Findings:** {counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
        f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low",
        "",
        "## Findings",
        "",
        "| Severity | CWE | File:Line | Title | Remediation |",
        "|---|---|---|---|---|",
    ]
    for f in report.findings:
        lines.append(f"| {f.severity} | {f.cwe} | `{f.file}:{f.line}` | {f.title} | {f.remediation} |")
    if not report.findings:
        lines.append("| — | — | — | No findings | — |")

    lines += ["", "## Review", "", report.narrative]
    return "\n".join(lines)


def write_json(report: AgentReport, path: str | Path) -> None:
    Path(path).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
