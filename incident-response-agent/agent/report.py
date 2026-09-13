"""Render an :class:`~agent.engine.InvestigationReport` as Markdown or JSON."""

from __future__ import annotations

import json

from .engine import InvestigationReport


def to_json(report: InvestigationReport) -> str:
    payload = {
        "alert": report.alert,
        "verdict": report.verdict,
        "severity": report.severity,
        "summary": report.summary,
        "truncated": report.truncated,
        "transcript": [
            {
                "step": t.step_number,
                "action": t.action,
                "tool": t.name,
                "arguments": t.arguments,
                "reasoning": t.reasoning,
                "observation": t.observation,
                "error": t.error,
            }
            for t in report.transcript
        ],
    }
    return json.dumps(payload, indent=2)


def to_markdown(report: InvestigationReport) -> str:
    lines = [
        f"# Incident Investigation: {report.alert.get('title', report.alert.get('host', 'unknown'))}",
        "",
        f"**Verdict:** {report.verdict.upper()}  ",
        f"**Severity:** {report.severity.upper()}  ",
        f"**Host:** {report.alert.get('host', 'n/a')}",
        "",
        "## Summary",
        report.summary,
        "",
        "## Investigation transcript",
    ]

    for t in report.transcript:
        if t.action == "final":
            lines.append(f"{t.step_number}. **Conclusion** — {t.reasoning}")
            continue
        header = f"{t.step_number}. `{t.name}({t.arguments})`"
        if t.reasoning:
            header += f" — {t.reasoning}"
        lines.append(header)
        if t.error:
            lines.append(f"   - error: {t.error}")
        elif t.observation is not None:
            lines.append(f"   - observation: `{json.dumps(t.observation)}`")

    if report.truncated:
        lines += ["", "> Investigation was truncated before reaching a conclusion."]

    return "\n".join(lines)
