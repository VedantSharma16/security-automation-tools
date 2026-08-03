"""Turning a list of Findings into console output, JSON, and a risk score."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .rules import SEVERITY_RANK

_SEVERITY_COLOR = {
    "low": "\033[36m",       # cyan
    "medium": "\033[33m",    # yellow
    "high": "\033[31m",      # red
    "critical": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"

# Weighted so that a handful of critical findings dominate the score the
# way they should dominate an analyst's attention, while still leaving room
# for "clean-ish, but noisy" repos to land in the middle of the scale.
_SEVERITY_WEIGHT = {"low": 2, "medium": 8, "high": 20, "critical": 35}


def risk_score(findings: list) -> int:
    if not findings:
        return 0
    raw = sum(_SEVERITY_WEIGHT[f.severity] for f in findings)
    return min(100, raw)


def highest_severity(findings: list):
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: SEVERITY_RANK[s])


def build_report(findings: list, *, scan_targets: dict) -> dict:
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_RANK[f.severity], reverse=True)
    by_severity = {sev: 0 for sev in SEVERITY_RANK}
    for f in findings:
        by_severity[f.severity] += 1

    return {
        "scanned_at": datetime.now(tz=timezone.utc).isoformat(),
        "targets": scan_targets,
        "finding_count": len(findings),
        "findings_by_severity": by_severity,
        "highest_severity": highest_severity(findings),
        "risk_score": risk_score(findings),
        "findings": [f.to_dict() for f in findings_sorted],
    }


def filter_by_min_severity(report: dict, min_severity: str) -> dict:
    threshold = SEVERITY_RANK[min_severity]
    filtered = [f for f in report["findings"] if SEVERITY_RANK[f["severity"]] >= threshold]
    report = dict(report)
    report["findings"] = filtered
    report["finding_count"] = len(filtered)
    return report


def render_console(report: dict, *, use_color: bool = True) -> str:
    lines = [f"secretscan — scan at {report['scanned_at']}"]
    targets = report["targets"]
    if targets.get("working_tree"):
        lines.append(f"Working tree      : {targets['working_tree']}")
    if targets.get("git_history"):
        lines.append("Git history       : scanned (all branches)" if targets.get("all_branches") else "Git history       : scanned (current branch)")
    lines.append(f"Findings          : {report['finding_count']}")
    lines.append(f"Risk score        : {report['risk_score']}/100")

    if not report["findings"]:
        lines.append("No secrets detected. ✅")
        return "\n".join(lines)

    lines.append("")
    for f in report["findings"]:
        color = _SEVERITY_COLOR.get(f["severity"], "") if use_color else ""
        reset = _RESET if use_color else ""
        location = f"{f['file']}:{f['line']}"
        if f.get("commit"):
            location += f" (commit {f['commit']})"
        lines.append(f"{color}[{f['severity'].upper():8}]{reset} {f['rule_id']} — {location}")
        lines.append(f"           {f['description']}")
        lines.append(f"           secret: {f['secret']}   context: {f['context']}")

    lines.append("")
    sev = report["findings_by_severity"]
    lines.append(
        f"Summary: {sev['critical']} critical, {sev['high']} high, "
        f"{sev['medium']} medium, {sev['low']} low."
    )
    return "\n".join(lines)


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
