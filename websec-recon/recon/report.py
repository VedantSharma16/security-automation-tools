"""Aggregating per-module findings into one report: console, markdown, JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .findings import SEVERITIES, Finding, score_findings

_SEVERITY_COLOR = {
    "info": "\033[37m",       # white
    "low": "\033[36m",        # cyan
    "medium": "\033[33m",     # yellow
    "high": "\033[31m",       # red
    "critical": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"
_SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITIES)}


def build_report(target: str, findings: list[Finding], scanned_at: datetime | None = None) -> dict:
    scanned_at = scanned_at or datetime.now(timezone.utc)
    findings_sorted = sorted(findings, key=lambda f: _SEVERITY_RANK[f.severity], reverse=True)
    risk = score_findings(findings)

    return {
        "target": target,
        "scanned_at": scanned_at.isoformat(),
        "finding_count": len(findings),
        "risk": risk,
        "findings": [f.to_dict() for f in findings_sorted],
    }


def filter_by_min_severity(report: dict, min_severity: str) -> dict:
    threshold = _SEVERITY_RANK[min_severity]
    filtered = [f for f in report["findings"] if _SEVERITY_RANK[f["severity"]] >= threshold]
    report = dict(report)
    report["findings"] = filtered
    report["finding_count"] = len(filtered)
    return report


def render_console(report: dict, use_color: bool = True) -> str:
    lines = []
    lines.append(f"websec-recon — {report['target']} — scanned {report['scanned_at']}")
    lines.append(f"Findings   : {report['finding_count']}")
    lines.append(f"Risk score : {report['risk']['score']}/100 ({report['risk']['label']})")

    if not report["findings"]:
        lines.append("No findings. ✅")
        return "\n".join(lines)

    lines.append("")
    for f in report["findings"]:
        color = _SEVERITY_COLOR.get(f["severity"], "") if use_color else ""
        reset = _RESET if use_color else ""
        lines.append(f"{color}[{f['severity'].upper():8}]{reset} ({f['category']}) {f['title']}")
        lines.append(f"           {f['description']}")
        if f["recommendation"]:
            lines.append(f"           fix: {f['recommendation']}")

    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    lines = [f"# websec-recon report: {report['target']}", ""]
    lines.append(f"- **Scanned at:** {report['scanned_at']}")
    lines.append(f"- **Findings:** {report['finding_count']}")
    lines.append(
        f"- **Risk score:** {report['risk']['score']}/100 (**{report['risk']['label'].upper()}**)"
    )
    lines.append("")

    if not report["findings"]:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    lines.append("| Severity | Category | Title | Description | Recommendation |")
    lines.append("|---|---|---|---|---|")
    for f in report["findings"]:
        lines.append(
            f"| {f['severity'].upper()} | {f['category']} | {f['title']} | "
            f"{f['description']} | {f['recommendation']} |"
        )

    return "\n".join(lines) + "\n"


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)


def write_markdown(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(report))
