"""Human-readable rendering of an :class:`~phishing_agent.agent.AgentResult`."""

from __future__ import annotations

from phishing_agent.agent import AgentResult
from phishing_agent.email_parser import ParsedEmail

_VERDICT_ICONS = {
    "phishing": "🔴",
    "suspicious": "🟠",
    "benign": "🟢",
}


def render_human(email: ParsedEmail, result: AgentResult) -> str:
    icon = _VERDICT_ICONS.get(result.verdict, "")
    lines = [
        f"{icon} Verdict: {result.verdict.upper()}  (confidence {result.confidence:.0%})",
        f"Agent mode: {'live (LLM tool-use)' if result.live else 'offline (deterministic sweep)'}",
        f"Subject: {email.subject!r}  From: {email.from_display} <{email.from_addr}>",
        "",
        "Reasoning:",
        f"  {result.reasoning}",
        "",
        "Key evidence:",
    ]
    if result.key_evidence:
        lines += [f"  - {item}" for item in result.key_evidence]
    else:
        lines.append("  (none)")

    lines += ["", f"Investigation trace ({len(result.trace)} tool call(s)):"]
    for i, step in enumerate(result.trace, start=1):
        lines.append(f"  {i}. {step.tool}")

    if result.note:
        lines += ["", f"Note: {result.note}"]

    return "\n".join(lines)
