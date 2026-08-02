"""Turning scan findings into console output and structured JSON reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .rules import SEVERITY_RANK

_SEVERITY_COLOR = {
    "low": "\033[36m",  # cyan
    "medium": "\033[33m",  # yellow
    "high": "\033[31m",  # red
    "critical": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"


def highest_severity(findings: list):
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: SEVERITY_RANK[s])


def build_report(findings: list, triage: dict = None, scanned_at: float = 0.0) -> dict:
    triage = triage or {}
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_RANK[f.severity], reverse=True)

    by_severity = {sev: 0 for sev in SEVERITY_RANK}
    for f in findings_sorted:
        by_severity[f.severity] += 1

    finding_dicts = []
    for f in findings_sorted:
        entry = {
            "rule_id": f.rule_id,
            "severity": f.severity,
            "category": f.category,
            "description": f.description,
            "detector": f.detector,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "preview": f.preview,
            "fingerprint": f.fingerprint,
            "commit": f.commit,
            "author": f.author,
            "date": f.date,
        }
        result = triage.get(f.fingerprint)
        if result is not None:
            entry["triage"] = {
                "verdict": result.verdict,
                "rationale": result.rationale,
                "source": result.source,
            }
        finding_dicts.append(entry)

    return {
        "scanned_at": datetime.fromtimestamp(scanned_at, tz=timezone.utc).isoformat(),
        "finding_count": len(finding_dicts),
        "highest_severity": highest_severity(findings_sorted),
        "by_severity": by_severity,
        "findings": finding_dicts,
    }


def filter_by_min_severity(report: dict, min_severity: str) -> dict:
    threshold = SEVERITY_RANK[min_severity]
    filtered = [f for f in report["findings"] if SEVERITY_RANK[f["severity"]] >= threshold]
    report = dict(report)
    report["findings"] = filtered
    report["finding_count"] = len(filtered)
    return report


def render_console(report: dict, use_color: bool = True) -> str:
    lines = [f"Secrets Scanner — scan at {report['scanned_at']}"]
    lines.append(f"Findings: {report['finding_count']}")

    if not report["findings"]:
        lines.append("No secrets detected. ✅")
        return "\n".join(lines)

    counts = ", ".join(f"{sev}={n}" for sev, n in report["by_severity"].items() if n)
    lines.append(f"By severity: {counts}")
    lines.append("")

    for f in report["findings"]:
        color = _SEVERITY_COLOR.get(f["severity"], "") if use_color else ""
        reset = _RESET if use_color else ""
        location = f"{f['file_path']}:{f['line_number']}"
        if f.get("commit"):
            location += f" (commit {f['commit']})"
        lines.append(
            f"{color}[{f['severity'].upper():8}]{reset} {f['rule_id']} — {location}"
        )
        lines.append(f"           {f['description']}")
        lines.append(f"           preview: {f['preview']}")
        triage = f.get("triage")
        if triage:
            lines.append(
                f"           triage ({triage['source']}): {triage['verdict']} — {triage['rationale']}"
            )

    return "\n".join(lines)


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
