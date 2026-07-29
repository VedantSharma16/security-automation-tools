"""Turning scan results into console output and structured JSON reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .patterns import SEVERITY_RANK
from .scanner import Finding

_SEVERITY_COLOR = {
    "low": "\033[36m",        # cyan
    "medium": "\033[33m",     # yellow
    "high": "\033[31m",       # red
    "critical": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"

_RISK_WEIGHT = {"low": 5, "medium": 15, "high": 30, "critical": 50}


def _summarize(findings: list[Finding]) -> dict:
    by_severity = {s: 0 for s in SEVERITY_RANK}
    for f in findings:
        by_severity[f.severity] += 1

    risk_score = min(100, sum(_RISK_WEIGHT[f.severity] for f in findings))
    highest = max((f.severity for f in findings), key=lambda s: SEVERITY_RANK[s], default=None)

    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "risk_score": risk_score,
        "highest_severity": highest,
    }


def build_report(findings: list[Finding], scan_type: str, targets: list[str]) -> dict:
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_RANK[f.severity], reverse=True)
    return {
        "scanned_at": datetime.now(tz=timezone.utc).isoformat(),
        "scan_type": scan_type,
        "targets": targets,
        "finding_count": len(findings),
        "summary": _summarize(findings),
        "findings": [f.to_dict() for f in findings_sorted],
    }


def filter_by_min_severity(report: dict, min_severity: str) -> dict:
    threshold = SEVERITY_RANK[min_severity]
    filtered = [f for f in report["findings"] if SEVERITY_RANK[f["severity"]] >= threshold]
    report = dict(report)
    report["findings"] = filtered
    report["finding_count"] = len(filtered)
    return report


def render_console(report: dict, use_color: bool = True) -> str:
    lines = [
        f"Secret Sentinel — {report['scan_type']} scan at {report['scanned_at']}",
        f"Targets           : {', '.join(report['targets'])}",
        f"Findings          : {report['finding_count']}",
    ]

    if not report["findings"]:
        lines.append("No secrets detected. ✅")
        return "\n".join(lines)

    summary = report["summary"]
    lines.append(
        f"Risk score        : {summary['risk_score']}/100 "
        f"(highest severity: {summary['highest_severity']})"
    )
    lines.append("")

    for f in report["findings"]:
        color = _SEVERITY_COLOR.get(f["severity"], "") if use_color else ""
        reset = _RESET if use_color else ""
        location = f"{f['file']}:{f['line_number']}"
        commit_suffix = f" (commit {f['commit']})" if f.get("commit") else ""
        lines.append(
            f"{color}[{f['severity'].upper():8}]{reset} {f['signature_id']} "
            f"— {location}{commit_suffix}"
        )
        lines.append(f"           {f['description']}")
        lines.append(f"           value={f['redacted_value']}  entropy={f['entropy']}")
        triage = f.get("llm_triage")
        if triage:
            lines.append(f"           triage={triage['verdict']}: {triage['rationale']}")

    return "\n".join(lines)


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
