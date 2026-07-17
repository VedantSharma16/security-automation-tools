"""Renders a Report as Markdown or JSON for CLI output."""

from __future__ import annotations

import json

from log_triage_agent.models import Report


def to_markdown(report: Report) -> str:
    lines = ["# Log Triage Report", ""]

    highest = report.highest_severity()
    lines.append(f"**Events analyzed:** {report.events_analyzed}  ")
    lines.append(f"**Findings:** {len(report.findings)}  ")
    lines.append(f"**Highest severity:** {highest.value.upper() if highest else 'NONE'}  ")
    lines.append(f"**Narrative source:** {report.narrative_source}")
    lines.append("")

    if report.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Severity | Title | ATT&CK | Events | First seen | Last seen |")
        lines.append("|---|---|---|---|---|---|")
        for f in report.findings:
            lines.append(
                f"| {f.severity.value.upper()} | {f.title} | {f.technique_id} ({f.technique_name}) "
                f"| {f.event_count} | {f.first_seen} | {f.last_seen} |"
            )
        lines.append("")

    if report.iocs.source_ips or report.iocs.usernames:
        lines.append("## Indicators of Compromise")
        lines.append("")
        if report.iocs.source_ips:
            lines.append(f"- **Source IPs:** {', '.join(report.iocs.source_ips)}")
        if report.iocs.usernames:
            lines.append(f"- **Usernames targeted:** {', '.join(report.iocs.usernames)}")
        lines.append("")

    lines.append("## Analyst Summary")
    lines.append("")
    lines.append(report.narrative)
    lines.append("")

    return "\n".join(lines)


def to_json(report: Report) -> str:
    payload = {
        "events_analyzed": report.events_analyzed,
        "highest_severity": (report.highest_severity().value if report.highest_severity() else None),
        "narrative_source": report.narrative_source,
        "findings": [f.to_dict() for f in report.findings],
        "iocs": report.iocs.to_dict(),
        "narrative": report.narrative,
    }
    return json.dumps(payload, indent=2)
