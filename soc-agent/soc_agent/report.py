"""Rendering an InvestigationResult as human-readable text or JSON."""

from __future__ import annotations

import json

from .agent import InvestigationResult

_SEVERITY_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
_VERDICT_ICONS = {"malicious": "☠️", "suspicious": "⚠️", "benign": "✅", "inconclusive": "❔"}


def to_dict(result: InvestigationResult) -> dict:
    return {
        "verdict": result.verdict,
        "severity": result.severity,
        "confidence": result.confidence,
        "summary": result.summary,
        "recommended_actions": result.recommended_actions,
        "llm_backed": result.llm_backed,
        "steps": [
            {
                "step": s.step,
                "thought": s.thought,
                "action": s.action,
                "action_input": s.action_input,
                "observation": s.observation,
            }
            for s in result.steps
        ],
    }


def render_json(result: InvestigationResult) -> str:
    return json.dumps(to_dict(result), indent=2)


def render_text(result: InvestigationResult, show_trace: bool = True) -> str:
    v_icon = _VERDICT_ICONS.get(result.verdict, "")
    s_icon = _SEVERITY_ICONS.get(result.severity, "")
    lines = [
        f"{v_icon} Verdict: {result.verdict.upper()}   {s_icon} Severity: {result.severity.upper()}   Confidence: {result.confidence}",
        f"Agent brain: {'live LLM tool-calling' if result.llm_backed else 'offline deterministic (no API key)'}",
        "",
    ]

    if show_trace:
        lines.append(f"Investigation trace ({len(result.steps)} step(s)):")
        if not result.steps:
            lines.append("  (no tool calls made)")
        for s in result.steps:
            lines.append(f"  [{s.step}] Thought: {s.thought}")
            lines.append(f"      Action: {s.action}({s.action_input})")
            lines.append(f"      Observation: {s.observation}")
        lines.append("")

    lines.append("Summary:")
    lines.append(f"  {result.summary}")
    lines.append("")
    lines.append("Recommended actions:")
    for action in result.recommended_actions:
        lines.append(f"  - {action}")
    return "\n".join(lines)
