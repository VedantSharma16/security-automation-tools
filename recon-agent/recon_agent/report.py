"""Turning agent state into console output, Markdown, and JSON reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .agent import AgentState
from .models import SEVERITY_RANK

_SEVERITY_COLOR = {
    "info": "\033[37m",       # white
    "low": "\033[36m",        # cyan
    "medium": "\033[33m",     # yellow
    "high": "\033[31m",       # red
    "critical": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"


def highest_severity(findings: list) -> str | None:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: SEVERITY_RANK[s])


def build_report(state: AgentState) -> dict:
    findings_sorted = sorted(state.findings, key=lambda f: SEVERITY_RANK[f.severity], reverse=True)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": state.host,
        "completed": state.done,
        "step_count": len(state.steps),
        "finding_count": len(findings_sorted),
        "highest_severity": highest_severity(findings_sorted),
        "steps": [s.to_dict() for s in state.steps],
        "findings": [f.to_dict() for f in findings_sorted],
    }


def render_console(report: dict, use_color: bool = True) -> str:
    lines = [
        f"Recon Agent — {report['host']} ({report['generated_at']})",
        f"Steps taken : {report['step_count']} (completed={report['completed']})",
        f"Findings    : {report['finding_count']}",
    ]

    if not report["findings"]:
        lines.append("No header/TLS findings. ✅")
    else:
        lines.append("")
        for f in report["findings"]:
            color = _SEVERITY_COLOR.get(f["severity"], "") if use_color else ""
            reset = _RESET if use_color else ""
            lines.append(f"{color}[{f['severity'].upper():8}]{reset} {f['id']} — {f['title']}")
            lines.append(f"           evidence: {f['evidence']}")
            lines.append(f"           fix     : {f['recommendation']}")

    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    lines = [
        f"# Recon report — {report['host']}",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Steps taken: {report['step_count']} (completed: {report['completed']})",
        f"- Findings: {report['finding_count']} (highest severity: {report['highest_severity'] or 'none'})",
        "",
        "## Findings",
        "",
    ]

    if not report["findings"]:
        lines.append("No header/TLS findings.")
    else:
        for f in report["findings"]:
            lines.append(f"### [{f['severity'].upper()}] {f['title']} (`{f['id']}`)")
            lines.append("")
            lines.append(f"- **Evidence:** {f['evidence']}")
            lines.append(f"- **Source:** {f['source_url']}")
            lines.append(f"- **Recommendation:** {f['recommendation']}")
            lines.append("")

    lines.append("## Steps")
    lines.append("")
    for i, step in enumerate(report["steps"], start=1):
        lines.append(f"{i}. `{step['tool']}({step['args']})` — {step['note']}")

    return "\n".join(lines)


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)


def write_markdown(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(report))
