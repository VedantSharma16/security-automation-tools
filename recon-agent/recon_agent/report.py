"""Render a :class:`~recon_agent.agent.ReconReport` as text/Markdown or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict

from .agent import ReconReport

_SEVERITY_ICON = {"info": "⚪", "low": "🟢", "medium": "🟡", "high": "🔴"}


def to_dict(report: ReconReport) -> dict:
    return {
        "target": report.target,
        "is_live": report.is_live,
        "risk": {
            "score": report.risk.score,
            "severity": report.risk.severity,
            "findings": [asdict(f) for f in report.risk.findings],
        }
        if report.risk
        else None,
        "trace": [
            {"tool": step.tool, "arguments": step.arguments, "result": step.result}
            for step in report.trace
        ],
        "narrative": report.narrative,
    }


def to_json(report: ReconReport) -> str:
    return json.dumps(to_dict(report), indent=2, default=str)


def to_markdown(report: ReconReport) -> str:
    lines = [f"# Passive recon report: {report.target}", ""]

    icon = _SEVERITY_ICON.get(report.risk.severity, "⚪") if report.risk else "⚪"
    mode = "agentic LLM tool-use loop" if report.is_live else "offline deterministic plan"
    lines.append(f"{icon} **Risk: {report.risk.severity.upper()}** (score {report.risk.score}) — run mode: {mode}")
    lines.append("")

    lines.append("## Tool calls")
    if report.trace:
        for i, step in enumerate(report.trace, 1):
            args = ", ".join(f"{k}={v}" for k, v in step.arguments.items()) or "(no arguments)"
            lines.append(f"{i}. `{step.tool}({args})`")
    else:
        lines.append("_(no tool calls recorded)_")
    lines.append("")

    lines.append("## Findings")
    if report.risk and report.risk.findings:
        for f in report.risk.findings:
            lines.append(f"- (+{f.points}) {f.reason}")
    else:
        lines.append("- No notable issues surfaced by the scoring rules.")
    lines.append("")

    lines.append("## Analyst summary")
    lines.append(report.narrative)
    return "\n".join(lines)
