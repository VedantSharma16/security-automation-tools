"""Build a structured triage report from a parsed Message and its findings,
and render it as JSON or Markdown."""

from __future__ import annotations

import json
from datetime import datetime

from .detectors import Finding
from .parser import Message
from .scoring import build_summary
from .urls import defang


def build_report(msg: Message, findings: list[Finding]) -> dict:
    """Assemble the structured (LLM- and JSON-friendly) triage report."""
    return {
        "source_file": msg.source_file,
        "generated_at": datetime.now().isoformat(),
        "message": {
            "subject": msg.subject,
            "from_display": msg.from_display,
            "from_addr": msg.from_addr,
            "reply_to_addr": msg.reply_to_addr,
            "date": msg.date,
            "attachment_count": len(msg.attachments),
        },
        "findings": [f.to_dict() for f in findings],
        "summary": build_summary(findings),
        "narrative": None,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def to_markdown(report: dict) -> str:
    lines: list[str] = []
    msg = report["message"]
    lines.append(f"# Phishing Triage Report: {report['source_file']}")
    lines.append("")
    lines.append(f"Generated: {report['generated_at']}")
    lines.append(f"Subject: {msg['subject']!r}")
    lines.append(
        f"From: {msg['from_display']!r} <{defang(msg['from_addr']) if msg['from_addr'] else ''}>"
    )
    if msg["reply_to_addr"]:
        lines.append(f"Reply-To: {defang(msg['reply_to_addr'])}")
    lines.append(f"Attachments: {msg['attachment_count']}")
    lines.append("")

    summary = report["summary"]
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Verdict: **{summary['verdict'].upper()}**")
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
            technique = f" ({f['attack_technique']})" if f.get("attack_technique") else ""
            lines.append(f"### [{f['severity']}] {f['title']}{technique}")
            lines.append("")
            lines.append(f["description"])
            lines.append("")
            lines.append(f"- Evidence: `{json.dumps(f['evidence'])}`")
            lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No phishing indicators detected.")
        lines.append("")

    if report.get("narrative"):
        lines.append("## Analyst Narrative")
        lines.append("")
        lines.append(report["narrative"])
        lines.append("")

    return "\n".join(lines)
