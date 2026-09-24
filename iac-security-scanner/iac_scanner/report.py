"""Turning scan results into console, Markdown, and JSON reports."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from .models import SEVERITY_RANK

_SEVERITY_COLOR = {
    "low": "\033[36m",         # cyan
    "medium": "\033[33m",      # yellow
    "high": "\033[31m",        # red
    "critical": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"


def highest_severity(findings: list):
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: SEVERITY_RANK[s])


def build_report(resources: list, findings: list) -> dict:
    counts = Counter(f.severity for f in findings)
    return {
        "scanned_at": datetime.now(tz=timezone.utc).isoformat(),
        "resource_count": len(resources),
        "finding_count": len(findings),
        "highest_severity": highest_severity(findings),
        "severity_counts": {sev: counts.get(sev, 0) for sev in SEVERITY_RANK},
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "resource_address": f.resource_address,
                "resource_type": f.resource_type,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
                "references": list(f.references),
            }
            for f in findings
        ],
    }


def filter_by_min_severity(report: dict, min_severity: str) -> dict:
    threshold = SEVERITY_RANK[min_severity]
    kept = [f for f in report["findings"] if SEVERITY_RANK[f["severity"]] >= threshold]
    filtered = dict(report)
    filtered["findings"] = kept
    filtered["finding_count"] = len(kept)
    return filtered


def render_text(report: dict, use_color: bool = True) -> str:
    lines = [
        f"Scanned {report['resource_count']} resource(s) at {report['scanned_at']}",
        f"Findings: {report['finding_count']} "
        f"(highest severity: {report['highest_severity'] or 'none'})",
        "",
    ]
    for f in report["findings"]:
        color = _SEVERITY_COLOR[f["severity"]] if use_color else ""
        reset = _RESET if use_color else ""
        lines.append(f"[{color}{f['severity'].upper()}{reset}] {f['rule_id']} - {f['title']}")
        lines.append(f"  resource: {f['resource_address']} ({f['resource_type']})")
        lines.append(f"  {f['description']}")
        lines.append(f"  remediation: {f['remediation']}")
        lines.append("")
    if not report["findings"]:
        lines.append("No findings at or above the requested severity. Clean scan.")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(report: dict) -> str:
    lines = [
        "# IaC Security Scan Report",
        "",
        f"- Scanned at: {report['scanned_at']}",
        f"- Resources scanned: {report['resource_count']}",
        f"- Findings: {report['finding_count']}",
        f"- Highest severity: {report['highest_severity'] or 'none'}",
        "",
    ]
    if report["findings"]:
        lines += [
            "| Severity | Rule | Resource | Title |",
            "|---|---|---|---|",
        ]
        for f in report["findings"]:
            lines.append(
                f"| {f['severity'].upper()} | {f['rule_id']} | `{f['resource_address']}` | {f['title']} |"
            )
        lines.append("")
        lines.append("## Details")
        for f in report["findings"]:
            lines.append(f"\n### {f['rule_id']} - {f['title']}")
            lines.append(f"- **Severity:** {f['severity'].upper()}")
            lines.append(f"- **Resource:** `{f['resource_address']}` ({f['resource_type']})")
            lines.append(f"- **Issue:** {f['description']}")
            lines.append(f"- **Remediation:** {f['remediation']}")
            if f["references"]:
                lines.append(f"- **Reference:** {f['references'][0]}")
    else:
        lines.append("No findings at or above the requested severity. Clean scan.")
    return "\n".join(lines).rstrip() + "\n"


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
