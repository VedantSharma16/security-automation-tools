"""Render an InvestigationResult as JSON or a Markdown analyst report."""

from __future__ import annotations

import json

from investigator.state import InvestigationResult

_VERDICT_LABELS = {
    "true_positive": "TRUE POSITIVE",
    "false_positive": "FALSE POSITIVE",
    "needs_escalation": "NEEDS ESCALATION",
}


def to_json(result: InvestigationResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def to_markdown(result: InvestigationResult) -> str:
    alert = result.alert
    lines: list[str] = []
    lines.append(f"# Investigation Report: {alert.alert_id}")
    lines.append("")
    lines.append(f"**Verdict:** {_VERDICT_LABELS.get(result.verdict, result.verdict.upper())}  ")
    lines.append(f"**Confidence:** {result.confidence}  ")
    lines.append(f"**Risk score:** {result.risk_score}/100 ({result.risk_band})  ")
    lines.append(f"**Mode:** {result.mode}")
    lines.append("")
    lines.append("## Alert")
    lines.append("")
    lines.append(f"- Host: {alert.host or '(none given)'}")
    lines.append(f"- Indicators: {', '.join(alert.indicators) if alert.indicators else '(none given)'}")
    lines.append(f"- Description: {alert.description}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(result.summary)
    lines.append("")
    lines.append("## Investigation Trace")
    lines.append("")
    if result.trace:
        for i, step in enumerate(result.trace, start=1):
            lines.append(f"### Step {i}: `{step.tool}`")
            lines.append("")
            lines.append(f"_{step.reasoning}_")
            lines.append("")
            lines.append(f"- Input: `{json.dumps(step.input)}`")
            lines.append(f"- Output: `{json.dumps(step.output)}`")
            lines.append("")
    else:
        lines.append("No tool calls were made.")
        lines.append("")
    lines.append("## Recommended Actions")
    lines.append("")
    if result.recommended_actions:
        for action in result.recommended_actions:
            lines.append(f"- {action}")
    else:
        lines.append("- None.")
    lines.append("")

    return "\n".join(lines)
