"""Turn a ScanState into a JSON-serializable report, console output, and Markdown."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .planner import ScanState
from .scoring import build_summary

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_SEVERITY_COLOR = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[36m",
    "INFO": "\033[37m",
}
_RESET = "\033[0m"


def build_report(state: ScanState) -> dict:
    summary = build_summary(state.findings)
    findings_sorted = sorted(state.findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.name))
    return {
        "target": state.base_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "planner_mode": state.planner_mode,
        "http_status": state.target.status,
        "summary": summary,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.name,
                "category": f.category,
                "detail": f.detail,
                "recommendation": f.recommendation,
            }
            for f in findings_sorted
        ],
        "planner_trace": [{"tool": step.tool, "reason": step.reason} for step in state.trace],
        "agent_assessment": state.agent_assessment,
    }


def render_console(report: dict, min_severity: str = "info", use_color: bool = True) -> str:
    threshold = _SEVERITY_ORDER.index(min_severity.upper())
    shown = [f for f in report["findings"] if _SEVERITY_ORDER.index(f["severity"]) <= threshold]

    lines = [
        f"Attack Surface Mapper — {report['target']}",
        f"Scanned at        : {report['scanned_at']}",
        f"Planner mode      : {report['planner_mode']}",
        f"HTTP status       : {report['http_status']}",
        f"Risk score        : {report['summary']['risk_score']}/100 ({report['summary']['rating']})",
        f"Findings          : {report['summary']['total_findings']} total, {len(shown)} shown",
        "",
    ]

    if not shown:
        lines.append("No findings at or above the selected severity.")
    else:
        for f in shown:
            color = _SEVERITY_COLOR.get(f["severity"], "") if use_color else ""
            reset = _RESET if use_color else ""
            lines.append(f"{color}[{f['severity']:8}]{reset} ({f['category']}) {f['title']}")
            lines.append(f"           {f['detail']}")
            if f["recommendation"]:
                lines.append(f"           -> {f['recommendation']}")

    if report.get("agent_assessment"):
        lines += ["", "Planner assessment:", report["agent_assessment"]]

    if report["planner_trace"]:
        lines += ["", "Planner trace:"]
        for step in report["planner_trace"]:
            lines.append(f"  - {step['tool']}: {step['reason']}")

    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    lines = [
        f"# Attack Surface Report — {report['target']}",
        "",
        f"- **Scanned at:** {report['scanned_at']}",
        f"- **Planner mode:** {report['planner_mode']}",
        f"- **HTTP status:** {report['http_status']}",
        f"- **Risk score:** {report['summary']['risk_score']}/100 ({report['summary']['rating']})",
        f"- **Total findings:** {report['summary']['total_findings']}",
        "",
        "## Findings",
        "",
    ]

    if not report["findings"]:
        lines.append("No findings.")
    else:
        for f in report["findings"]:
            lines.append(f"### [{f['severity']}] {f['title']}")
            lines.append("")
            lines.append(f"- **Category:** {f['category']}")
            lines.append(f"- **Detail:** {f['detail']}")
            if f["recommendation"]:
                lines.append(f"- **Recommendation:** {f['recommendation']}")
            lines.append("")

    if report.get("agent_assessment"):
        lines += ["## Planner Assessment", "", report["agent_assessment"], ""]

    lines.append("## Planner Trace")
    lines.append("")
    for step in report["planner_trace"]:
        lines.append(f"1. `{step['tool']}` — {step['reason']}")

    return "\n".join(lines)


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)


def write_markdown(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(report))
