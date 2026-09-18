"""Build a structured remediation report from scored findings, and render it
as JSON or Markdown."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .scoring import ScoredFinding, build_summary


def build_report(scan_file: str | Path, assets_file: str | Path | None, scored: list[ScoredFinding]) -> dict:
    return {
        "scan_file": str(scan_file),
        "assets_file": str(assets_file) if assets_file else None,
        "generated_at": datetime.now().isoformat(),
        "summary": build_summary(scored),
        "findings": [sf.to_dict() for sf in scored],
        "narrative": None,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def to_markdown(report: dict, top_n: int | None = None) -> str:
    summary = report["summary"]
    findings = report["findings"]
    shown = findings[:top_n] if top_n else findings

    lines: list[str] = []
    lines.append(f"# Vulnerability Remediation Priority Report: {report['scan_file']}")
    lines.append("")
    lines.append(f"Generated: {report['generated_at']}")
    if report["assets_file"]:
        lines.append(f"Asset inventory: {report['assets_file']}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total findings: {summary['total_findings']}")
    lines.append(f"- Hosts affected: {summary['hosts_affected']}")
    lines.append(f"- Average priority score: {summary['average_priority_score']}/100")
    lines.append(f"- Findings with confirmed active exploitation (CISA KEV): {summary['kev_findings']}")
    lines.append("- By tier:")
    for tier, count in summary["by_tier"].items():
        if count:
            lines.append(f"  - {tier}: {count}")
    lines.append("")

    if shown:
        lines.append("## Prioritized Findings")
        lines.append("")
        for sf in shown:
            f = sf["finding"]
            cve = f["cve_id"] or "no CVE"
            lines.append(
                f"### [{sf['priority_tier']} — {sf['priority_score']}/100] "
                f"{f['title']} ({cve}) on {f['host']}"
            )
            lines.append("")
            lines.append(sf["priority_label"])
            lines.append("")
            for reason in sf["rationale"]:
                lines.append(f"- {reason}")
            lines.append("")
    else:
        lines.append("## Prioritized Findings")
        lines.append("")
        lines.append("No findings to report.")
        lines.append("")

    if report.get("narrative"):
        lines.append("## Executive Narrative")
        lines.append("")
        lines.append(report["narrative"])
        lines.append("")

    return "\n".join(lines)
