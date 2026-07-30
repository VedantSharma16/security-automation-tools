"""Render a ScanResult as a structured dict and as JSON/Markdown reports."""

from __future__ import annotations

import json

from .models import ScanResult
from .scoring import build_summary

# Sort findings worst-first for both the JSON payload and the Markdown report.
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def build_report(result: ScanResult) -> dict:
    findings = sorted(
        result.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity.name, 99)
    )
    return {
        "target": result.target,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "findings": [f.to_dict() for f in findings],
        "summary": build_summary(result.findings),
        "errors": list(result.errors),
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def to_markdown(report: dict) -> str:
    lines: list[str] = []
    lines.append(f"# Web Recon Report: {report['target']}")
    lines.append("")
    lines.append(f"Started:  {report['started_at']}")
    lines.append(f"Finished: {report['finished_at']}")
    lines.append("")

    if report["errors"]:
        lines.append("## Errors")
        lines.append("")
        for err in report["errors"]:
            lines.append(f"- {err}")
        lines.append("")

    summary = report["summary"]
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total findings: {summary['total_findings']}")
    lines.append(f"- Highest severity: {summary['highest_severity'] or 'None'}")
    lines.append(f"- Risk score: {summary['risk_score']}/100")
    for sev, count in summary["by_severity"].items():
        if count:
            lines.append(f"  - {sev}: {count}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if report["findings"]:
        for f in report["findings"]:
            lines.append(f"### [{f['severity']}] {f['title']}")
            lines.append("")
            lines.append(f["description"])
            lines.append("")
            if f["evidence"]:
                lines.append(f"- Evidence: `{f['evidence']}`")
            if f["remediation"]:
                lines.append(f"- Remediation: {f['remediation']}")
            if f["owasp_ref"]:
                lines.append(f"- Reference: {f['owasp_ref']}")
            lines.append("")
    else:
        lines.append("No findings — nothing to report.")
        lines.append("")

    return "\n".join(lines)
