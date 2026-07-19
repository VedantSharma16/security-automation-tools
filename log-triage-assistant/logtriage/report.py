"""Build a structured incident report from parsed events and detector findings,
and render it as JSON or Markdown."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .detectors import Finding
from .parser import Event
from .scoring import build_summary


def build_report(source_file: str | Path, events: list[Event], findings: list[Finding]) -> dict:
    """Assemble the structured (LLM- and JSON-friendly) incident report."""
    time_range = None
    if events:
        time_range = {
            "start": min(e.timestamp for e in events).isoformat(),
            "end": max(e.timestamp for e in events).isoformat(),
        }

    return {
        "source_file": str(source_file),
        "generated_at": datetime.now().isoformat(),
        "event_count": len(events),
        "time_range": time_range,
        "findings": [f.to_dict() for f in findings],
        "summary": build_summary(findings),
        "narrative": None,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def to_markdown(report: dict) -> str:
    lines: list[str] = []
    lines.append(f"# Incident Triage Report: {report['source_file']}")
    lines.append("")
    lines.append(f"Generated: {report['generated_at']}")
    lines.append(f"Events analyzed: {report['event_count']}")
    if report["time_range"]:
        lines.append(f"Time range: {report['time_range']['start']} to {report['time_range']['end']}")
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

    if report["findings"]:
        lines.append("## Findings")
        lines.append("")
        for f in report["findings"]:
            lines.append(f"### [{f['severity']}] {f['title']}")
            lines.append("")
            lines.append(f["description"])
            lines.append("")
            lines.append(f"- First seen: {f['first_seen']}")
            lines.append(f"- Last seen: {f['last_seen']}")
            lines.append(f"- Evidence: `{json.dumps(f['evidence'])}`")
            lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No security-relevant patterns detected.")
        lines.append("")

    if report.get("narrative"):
        lines.append("## Analyst Narrative")
        lines.append("")
        lines.append(report["narrative"])
        lines.append("")

    return "\n".join(lines)
