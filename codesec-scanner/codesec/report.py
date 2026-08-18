"""Aggregation and formatting of scan results."""

from __future__ import annotations

import json

from codesec.findings import ScanResult, Severity

_SEVERITY_ORDER = list(reversed(list(Severity)))


def to_json(result: ScanResult, narrative: str | None = None) -> str:
    payload = {
        "summary": {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "total_findings": len(result.findings),
            "by_severity": result.count_by_severity(),
        },
        "findings": [f.to_dict() for f in result.sorted_findings()],
    }
    if narrative:
        payload["narrative"] = narrative
    return json.dumps(payload, indent=2)


def to_text(result: ScanResult, narrative: str | None = None) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append("CODESEC SCAN REPORT")
    lines.append("=" * 72)
    lines.append(f"Files scanned: {result.files_scanned}  (skipped: {result.files_skipped})")
    lines.append(f"Total findings: {len(result.findings)}")

    counts = result.count_by_severity()
    breakdown = "  ".join(f"{sev.name}: {counts[sev.name]}" for sev in _SEVERITY_ORDER if counts[sev.name])
    if breakdown:
        lines.append(f"By severity: {breakdown}")
    lines.append("")

    if not result.findings:
        lines.append("No findings. ✔")
    else:
        for finding in result.sorted_findings():
            lines.append(f"[{finding.severity.name}] {finding.title} ({finding.cwe})")
            lines.append(f"  rule:     {finding.rule_id}")
            lines.append(f"  location: {finding.file}:{finding.line}")
            lines.append(f"  snippet:  {finding.snippet}")
            lines.append(f"  why:      {finding.description}")
            lines.append(f"  fix:      {finding.remediation}")
            lines.append("")

    if narrative:
        lines.append("-" * 72)
        lines.append("ANALYST NARRATIVE")
        lines.append("-" * 72)
        lines.append(narrative)

    return "\n".join(lines)


def render(result: ScanResult, fmt: str, narrative: str | None = None) -> str:
    if fmt == "json":
        return to_json(result, narrative)
    if fmt == "text":
        return to_text(result, narrative)
    raise ValueError(f"Unknown format: {fmt!r}. Expected 'text' or 'json'.")
