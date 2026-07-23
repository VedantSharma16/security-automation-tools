"""Build a structured triage report from a parsed email and its findings,
and render it as JSON or Markdown."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .heuristics import Finding
from .parser import ParsedEmail
from .scoring import build_summary


def build_report(source_file: str | Path, email: ParsedEmail, findings: list[Finding]) -> dict:
    """Assemble the structured (LLM- and JSON-friendly) phishing triage report."""
    return {
        "source_file": str(source_file),
        "generated_at": datetime.now().isoformat(),
        "sender": {
            "display_name": email.from_display_name,
            "address": email.from_address,
            "reply_to": email.reply_to_address or None,
        },
        "subject": email.subject,
        "date": email.date,
        "link_count": len(email.links),
        "attachment_count": len(email.attachments),
        "findings": [f.to_dict() for f in findings],
        "summary": build_summary(findings),
        "narrative": None,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def to_markdown(report: dict) -> str:
    lines: list[str] = []
    lines.append(f"# Phishing Triage Report: {report['source_file']}")
    lines.append("")
    lines.append(f"Generated: {report['generated_at']}")
    lines.append(f"From: {report['sender']['display_name']} <{report['sender']['address']}>")
    if report["sender"]["reply_to"]:
        lines.append(f"Reply-To: {report['sender']['reply_to']}")
    lines.append(f"Subject: {report['subject']}")
    if report["date"]:
        lines.append(f"Date: {report['date']}")
    lines.append(f"Links: {report['link_count']}  |  Attachments: {report['attachment_count']}")
    lines.append("")

    summary = report["summary"]
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Verdict: **{summary['verdict'].replace('_', ' ').upper()}**")
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
            lines.append(f"- Evidence: `{json.dumps(f['evidence'])}`")
            lines.append("")
    else:
        lines.append("No phishing indicators detected.")
        lines.append("")

    if report.get("narrative"):
        lines.append("## Analyst Narrative")
        lines.append("")
        lines.append(report["narrative"])
        lines.append("")

    return "\n".join(lines)
