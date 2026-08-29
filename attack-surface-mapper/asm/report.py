"""Assemble recon results into a structured report and render it as JSON/Markdown."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .findings import Finding, build_summary


def build_report(
    domain: str,
    dns_records: dict,
    subdomains: list[str],
    http_result: dict,
    tls_info: dict | None,
    findings: list[Finding],
) -> dict:
    findings_sorted = sorted(findings, key=lambda f: f.severity, reverse=True)
    return {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dns_records": dns_records,
        "subdomains": subdomains,
        "http": http_result,
        "tls": tls_info,
        "findings": [f.to_dict() for f in findings_sorted],
        "summary": build_summary(findings),
        "narrative": None,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def to_markdown(report: dict) -> str:
    lines: list[str] = []
    lines.append(f"# Attack Surface Report: {report['domain']}")
    lines.append("")
    lines.append(f"Generated: {report['generated_at']}")
    lines.append(f"Subdomains discovered: {len(report['subdomains'])}")
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
            lines.append(f"### [{f['severity']}] {f['title']} ({f['source']})")
            lines.append("")
            lines.append(f["detail"])
            lines.append("")
    else:
        lines.append("No findings.")
        lines.append("")

    if report.get("narrative"):
        lines.append("## Analyst Narrative")
        lines.append("")
        lines.append(report["narrative"])
        lines.append("")

    return "\n".join(lines)
