"""Turning scan results into console output and structured JSON reports."""

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


def highest_severity(findings: list):
    if not findings:
        return None
    return max((f.rule.severity for f in findings), key=lambda s: SEVERITY_RANK[s])


def build_report(processes: list, findings: list, new_processes: list, scanned_at: float) -> dict:
    findings_sorted = sorted(
        findings, key=lambda f: SEVERITY_RANK[f.rule.severity], reverse=True
    )
    return {
        "scanned_at": datetime.fromtimestamp(scanned_at, tz=timezone.utc).isoformat(),
        "process_count": len(processes),
        "finding_count": len(findings),
        "highest_severity": highest_severity(findings),
        "findings": [
            {
                "rule_id": f.rule.id,
                "severity": f.rule.severity,
                "mitre_tactic": f.rule.mitre_tactic,
                "mitre_technique": f.rule.mitre_technique,
                "description": f.rule.description,
                "matched_field": f.matched_field,
                "matched_text": f.matched_text,
                "process": {
                    "pid": f.process.pid,
                    "name": f.process.name,
                    "exe": f.process.exe,
                    "cmdline": f.process.cmdline,
                    "username": f.process.username,
                },
            }
            for f in findings_sorted
        ],
        "new_since_baseline": [
            {
                "pid": p.pid,
                "name": p.name,
                "exe": p.exe,
                "cmdline": p.cmdline,
                "username": p.username,
            }
            for p in new_processes
        ],
    }


def filter_by_min_severity(report: dict, min_severity: str) -> dict:
    threshold = SEVERITY_RANK[min_severity]
    filtered = [
        f for f in report["findings"] if SEVERITY_RANK[f["severity"]] >= threshold
    ]
    report = dict(report)
    report["findings"] = filtered
    report["finding_count"] = len(filtered)
    return report


def render_console(report: dict, use_color: bool = True) -> str:
    lines = []
    lines.append(f"Process Threat Hunter — scan at {report['scanned_at']}")
    lines.append(f"Processes scanned : {report['process_count']}")
    lines.append(f"Findings          : {report['finding_count']}")

    if not report["findings"]:
        lines.append("No rule matches. ✅")
    else:
        lines.append("")
        for f in report["findings"]:
            color = _SEVERITY_COLOR.get(f["severity"], "") if use_color else ""
            reset = _RESET if use_color else ""
            proc = f["process"]
            cmdline = " ".join(proc["cmdline"]) if proc["cmdline"] else proc["name"]
            lines.append(
                f"{color}[{f['severity'].upper():8}]{reset} {f['rule_id']} "
                f"({f['mitre_tactic']} / {f['mitre_technique']})"
            )
            lines.append(f"           pid={proc['pid']} user={proc['username']} cmd={cmdline}")
            lines.append(f"           matched '{f['matched_text']}' in {f['matched_field']}")

    if report["new_since_baseline"]:
        lines.append("")
        lines.append(f"New processes since baseline: {len(report['new_since_baseline'])}")
        for p in report["new_since_baseline"]:
            cmdline = " ".join(p["cmdline"]) if p["cmdline"] else p["name"]
            lines.append(f"           pid={p['pid']} user={p['username']} cmd={cmdline}")

    return "\n".join(lines)


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
