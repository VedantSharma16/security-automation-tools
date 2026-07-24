"""Render a ScanResult as JSON or a human-readable table."""

from __future__ import annotations

import json

from .models import Finding, ScanResult

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _sort_key(f: Finding):
    return (_SEVERITY_ORDER.get(f.severity, 4), f.file, f.line)


def severity_breakdown(findings: list[Finding]) -> dict:
    breakdown = {sev: 0 for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for f in findings:
        breakdown[f.severity] = breakdown.get(f.severity, 0) + 1
    return breakdown


def to_dict(result: ScanResult) -> dict:
    new = sorted(result.new_findings, key=_sort_key)
    baselined = sorted(result.baselined_findings, key=_sort_key)
    return {
        "summary": {
            "total_findings": len(result.findings),
            "new_findings": len(new),
            "baselined_findings": len(baselined),
            "by_severity": severity_breakdown(new),
        },
        "findings": [f.to_dict() for f in new],
        "baselined": [f.to_dict() for f in baselined],
    }


def to_json(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2)


def to_table(result: ScanResult, show_baselined: bool = False) -> str:
    findings = sorted(result.new_findings, key=_sort_key)
    if show_baselined:
        findings = findings + sorted(result.baselined_findings, key=_sort_key)

    if not findings:
        summary = severity_breakdown(result.new_findings)
        return (
            f"No new secrets found. "
            f"({len(result.baselined_findings)} baselined, suppressed)"
            if result.baselined_findings
            else "No secrets found."
        )

    headers = ["SEVERITY", "RULE", "LOCATION", "COMMIT", "SECRET", "STATUS"]
    rows = []
    for f in findings:
        location = f"{f.file}:{f.line}"
        commit = f.commit or "-"
        status = "baselined" if f.fingerprint in result.baselined_fingerprints else "NEW"
        rows.append([f.severity, f.rule_id, location, commit, f.redacted, status])

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(row):
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    lines = [fmt_row(headers), "  ".join("-" * w for w in widths)]
    lines.extend(fmt_row(r) for r in rows)

    breakdown = severity_breakdown(result.new_findings)
    lines.append("")
    lines.append(
        "Summary: {total} new finding(s) - CRITICAL={c} HIGH={h} MEDIUM={m} LOW={l}"
        " ({baselined} baselined, suppressed)".format(
            total=len(result.new_findings),
            c=breakdown["CRITICAL"],
            h=breakdown["HIGH"],
            m=breakdown["MEDIUM"],
            l=breakdown["LOW"],
            baselined=len(result.baselined_findings),
        )
    )
    return "\n".join(lines)
