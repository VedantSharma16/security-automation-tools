"""Render an AgentResult as a human-readable transcript or JSON."""

from __future__ import annotations

import json

from .models import AgentResult

_VERDICT_ICONS = {"escalate": "🔴", "monitor": "🟡", "close": "🟢"}


def render_human(result: AgentResult) -> str:
    icon = _VERDICT_ICONS.get(result.verdict, "")
    lines = [
        f"Alert {result.alert_id} — {icon} verdict: {result.verdict.upper()}",
        f"Backend: {result.backend}" + (f"  ({result.note})" if result.note else ""),
        "",
        "Investigation trace:",
    ]
    for step in result.steps:
        lines.append(f"  [{step.step_number}] {step.tool_name}({_fmt_args(step.tool_args)})")
        if step.thought:
            lines.append(f"      thought: {step.thought}")
        lines.append(f"      result: {json.dumps(step.tool_result)}")
    lines += ["", f"Reason: {result.reason}"]
    return "\n".join(lines)


def render_json(result: AgentResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def _fmt_args(args: dict) -> str:
    return ", ".join(f"{k}={v!r}" for k, v in args.items())
