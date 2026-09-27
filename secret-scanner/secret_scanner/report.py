"""Report assembly and rendering: console (colored), JSON, and Markdown."""

from __future__ import annotations

import json
from pathlib import Path

from .findings import SEVERITIES, SEVERITY_RANK, Finding, highest_severity, risk_score

_COLOR = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "reset": "\033[0m",
}

_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def build_report(
    working_tree_findings: list[Finding],
    history_findings: list[Finding] | None = None,
) -> dict:
    history_findings = history_findings or []
    all_findings = working_tree_findings + history_findings

    by_severity = {sev: 0 for sev in SEVERITIES}
    for f in all_findings:
        by_severity[f.severity] += 1

    return {
        "summary": {
            "total_findings": len(all_findings),
            "working_tree_findings": len(working_tree_findings),
            "git_history_findings": len(history_findings),
            "by_severity": by_severity,
            "highest_severity": highest_severity(all_findings),
            "risk_score": risk_score(all_findings),
        },
        "findings": [f.to_dict() for f in all_findings],
    }


def filter_by_min_severity(report: dict, min_severity: str) -> dict:
    min_rank = SEVERITY_RANK[min_severity]
    findings = [f for f in report["findings"] if SEVERITY_RANK[f["severity"]] >= min_rank]

    by_severity = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        by_severity[f["severity"]] += 1

    summary = dict(report["summary"])
    summary["by_severity"] = by_severity
    summary["total_findings"] = len(findings)
    summary["working_tree_findings"] = sum(1 for f in findings if f["source"] == "working_tree")
    summary["git_history_findings"] = sum(1 for f in findings if f["source"] == "git_history")
    summary["highest_severity"] = max((f["severity"] for f in findings), key=lambda s: SEVERITY_RANK[s], default=None)

    return {"summary": summary, "findings": findings}


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f["severity"]], f["file_path"], f["line_number"]))


def render_console(report: dict, use_color: bool = True) -> str:
    summary = report["summary"]
    lines = []

    def c(sev, text):
        if not use_color:
            return text
        return f"{_COLOR[sev]}{text}{_COLOR['reset']}"

    if summary["total_findings"] == 0:
        return "No secrets detected."

    lines.append(
        f"{summary['total_findings']} finding(s) "
        f"({summary['working_tree_findings']} in working tree, "
        f"{summary['git_history_findings']} in git history) -- "
        f"highest severity: {c(summary['highest_severity'], summary['highest_severity'].upper())}, "
        f"risk score {summary['risk_score']}/100"
    )
    lines.append("")

    for f in _sorted_findings(report["findings"]):
        icon = _ICON.get(f["severity"], "")
        location = f"{f['file_path']}:{f['line_number']}"
        if f["source"] == "git_history":
            commit = f["commit"]
            location += f" (commit {commit['hash']}, {commit['date']}, {commit['author']})"
        header = c(f["severity"], f"{icon} [{f['severity'].upper()}] {f['rule_id']}")
        lines.append(f"{header} -- {location}")
        lines.append(f"    {f['description']}: {f['redacted_value']}")

    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Secret Scan Report",
        "",
        f"**Total findings:** {summary['total_findings']} "
        f"({summary['working_tree_findings']} working tree, {summary['git_history_findings']} git history)",
        f"**Highest severity:** {summary['highest_severity'] or 'none'}",
        f"**Risk score:** {summary['risk_score']}/100",
        "",
    ]

    if summary["total_findings"] == 0:
        lines.append("No secrets detected.")
        return "\n".join(lines)

    lines += ["| Severity | Rule | Location | Value |", "|---|---|---|---|"]
    for f in _sorted_findings(report["findings"]):
        location = f"{f['file_path']}:{f['line_number']}"
        if f["source"] == "git_history":
            location += f" (`{f['commit']['hash']}`)"
        lines.append(f"| {f['severity']} | `{f['rule_id']}` | {location} | `{f['redacted_value']}` |")

    return "\n".join(lines)


def write_json(report: dict, path: "str | Path") -> None:
    Path(path).write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_markdown(report: dict, path: "str | Path") -> None:
    Path(path).write_text(render_markdown(report), encoding="utf-8")
