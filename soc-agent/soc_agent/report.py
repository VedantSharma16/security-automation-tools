"""Render an investigation's verdict + transcript as text or a JSON-able dict."""

from __future__ import annotations

from .tools import Verdict

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def to_dict(verdict: Verdict, transcript: list, alert_text: str, mode: str) -> dict:
    return {
        "mode": mode,
        "alert_text": alert_text,
        "verdict": verdict.to_dict(),
        "transcript": [step.to_dict() for step in transcript],
    }


def render_text(verdict: Verdict, transcript: list, mode: str, show_transcript: bool = True) -> str:
    lines = [
        "=" * 60,
        f"SOC AGENT INVESTIGATION REPORT  [{mode} mode]",
        "=" * 60,
        f"Severity: {verdict.severity.upper()}",
        f"Steps taken: {verdict.steps_taken}",
        "",
        "Summary:",
        f"  {verdict.summary}",
        "",
        "Key indicators:",
    ]
    lines += [f"  - {ind}" for ind in verdict.key_indicators] or ["  (none)"]

    lines.append("")
    lines.append("Matched ATT&CK techniques:")
    lines += [f"  - {t}" for t in verdict.matched_techniques] or ["  (none)"]

    lines.append("")
    lines.append("Recommended actions:")
    lines += [f"  {i + 1}. {a}" for i, a in enumerate(verdict.recommended_actions)]

    if show_transcript:
        lines.append("")
        lines.append("-" * 60)
        lines.append("Investigation transcript (tool calls the agent made):")
        for i, step in enumerate(transcript, 1):
            lines.append(f"  [{i}] {step.tool}({_format_args(step.arguments)})")
            lines.append(f"      -> {_truncate(str(step.result))}")

    return "\n".join(lines)


def exit_code_for(verdict: Verdict, min_fail_severity: str) -> int:
    """0 if severity is below the threshold, 1 if at/above it."""
    return 1 if _SEVERITY_ORDER[verdict.severity] >= _SEVERITY_ORDER[min_fail_severity] else 0


def _format_args(args: dict) -> str:
    return ", ".join(f"{k}={v!r}" for k, v in args.items())


def _truncate(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."
