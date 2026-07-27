"""Render an :class:`~soc_agent.playbook.IncidentReport` as Markdown or JSON."""

from __future__ import annotations

import dataclasses
import json

from .playbook import IncidentReport

VERDICT_ICONS = {"benign": "🟢", "suspicious": "🟡", "malicious": "🔴"}


def render_markdown(report: IncidentReport) -> str:
    alert = report.alert
    icon = VERDICT_ICONS.get(report.verdict, "⚪")

    lines = [
        f"# Incident Report — {alert.alert_id}",
        "",
        f"{icon} **Verdict:** {report.verdict.upper()}  ",
        f"**Confidence:** {report.confidence}  ",
        f"**Score:** {report.score}  ",
        f"**Mode:** {report.mode}",
        "",
        "## Alert",
        f"- Description: {alert.description}",
    ]
    for label, value in (
        ("Timestamp", alert.timestamp),
        ("Hostname", alert.hostname),
        ("Source IP", alert.source_ip),
        ("Dest IP", alert.dest_ip),
        ("User", alert.username),
        ("Process", alert.process_name),
    ):
        if value:
            lines.append(f"- {label}: {value}")

    lines += ["", "## Investigation trace"]
    if report.trace:
        for i, step in enumerate(report.trace, 1):
            arg_str = ", ".join(f"{k}={v!r}" for k, v in step.arguments.items())
            lines.append(f"{i}. `{step.tool}({arg_str})` → `{json.dumps(step.result)}`")
    else:
        lines.append("- (no tool calls made)")

    lines += ["", "## Evidence"]
    lines += [f"- {e}" for e in report.evidence]

    lines += ["", "## Recommended actions"]
    lines += [f"- {a}" for a in report.recommended_actions]

    if report.warnings:
        lines += ["", "## Warnings"]
        lines += [f"- {w}" for w in report.warnings]

    return "\n".join(lines) + "\n"


def render_json(report: IncidentReport) -> str:
    return json.dumps(dataclasses.asdict(report), indent=2)
