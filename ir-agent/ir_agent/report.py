"""Render an AgentResult as a human-readable report or JSON."""

from __future__ import annotations

import json

from .agent import AgentResult

_SEVERITY_ICONS = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\U0001f7e2",
}


def to_json(result: AgentResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent)


def to_markdown(result: AgentResult, include_transcript: bool = True) -> str:
    icon = _SEVERITY_ICONS.get(result.severity, "")
    lines = [
        f"# Incident Report {icon}".rstrip(),
        "",
        f"**Severity:** {result.severity.upper()}",
        f"**Agent mode:** {result.mode}",
        "",
        "## Summary",
        result.summary,
        "",
        "## Key indicators",
    ]
    if result.key_indicators:
        lines += [f"- {value}" for value in result.key_indicators]
    else:
        lines.append("- (none)")

    lines += ["", "## MITRE ATT&CK techniques"]
    if result.attack_techniques:
        lines += [f"- {technique_id}" for technique_id in result.attack_techniques]
    else:
        lines.append("- (none matched)")

    lines += ["", "## Recommended actions"]
    lines += [f"{i}. {action}" for i, action in enumerate(result.recommended_actions, start=1)]

    if include_transcript and result.transcript:
        lines += ["", "## Investigation transcript"]
        for i, call in enumerate(result.transcript, start=1):
            lines.append(f"{i}. `{call.tool}` called with `{json.dumps(_truncate_input(call.input))}`")

    return "\n".join(lines)


def _truncate_input(tool_input: dict, max_len: int = 60) -> dict:
    """Shorten long free-text fields (e.g. raw incident text) for transcript display."""
    truncated = {}
    for key, value in tool_input.items():
        if isinstance(value, str) and len(value) > max_len:
            truncated[key] = value[:max_len] + "..."
        else:
            truncated[key] = value
    return truncated
