"""Assemble every analyzer's output into one report dict, and render it."""

from __future__ import annotations

import json

from .auth_analysis import AuthResult
from .content_analysis import AttachmentFinding, ContentFindings, SenderFinding
from .parser import ParsedEmail
from .scoring import TriageResult
from .url_analysis import UrlFinding

_VERDICT_COLOR = {
    "benign": "\033[32m",           # green
    "suspicious": "\033[33m",       # yellow
    "likely_phishing": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"


def build_report(
    parsed: ParsedEmail,
    auth: AuthResult,
    url_findings: list[UrlFinding],
    content: ContentFindings,
    sender: SenderFinding,
    attachment_findings: list[AttachmentFinding],
    triage: TriageResult,
) -> dict:
    return {
        "email": {
            "from_display": parsed.from_display,
            "from_addr": parsed.from_addr,
            "from_domain": parsed.from_domain,
            "reply_to_addr": parsed.reply_to_addr,
            "to_addrs": list(parsed.to_addrs),
            "subject": parsed.subject,
            "date": parsed.date,
            "message_id": parsed.message_id,
            "received_count": parsed.received_count,
            "link_count": len(parsed.links),
            "attachment_count": len(parsed.attachments),
        },
        "authentication": auth.as_dict(),
        "sender": sender.as_dict(),
        "url_findings": [f.as_dict() for f in url_findings],
        "content_findings": content.as_dict(),
        "attachment_findings": [f.as_dict() for f in attachment_findings],
        "triage": triage.as_dict(),
        "narrative": None,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def render_console(report: dict, use_color: bool = True) -> str:
    triage = report["triage"]
    email = report["email"]
    auth = report["authentication"]

    color = _VERDICT_COLOR.get(triage["verdict"], "") if use_color else ""
    reset = _RESET if use_color else ""

    lines = [
        "Phishing Triage Report",
        f"From    : {email['from_display']} <{email['from_addr']}>",
        f"Subject : {email['subject']}",
        f"Verdict : {color}{triage['verdict'].replace('_', ' ').upper()}{reset} "
        f"(score {triage['score']}/100)",
        f"Auth    : spf={auth['spf']} dkim={auth['dkim']} dmarc={auth['dmarc']} "
        f"(header present: {auth['header_present']})",
        f"Links   : {email['link_count']}   Attachments: {email['attachment_count']}",
    ]

    if triage["reasons"]:
        lines.append("")
        lines.append("Findings:")
        for reason in triage["reasons"]:
            lines.append(f"  - {reason}")
    else:
        lines.append("")
        lines.append("No indicators flagged.")

    if report.get("narrative"):
        lines.append("")
        lines.append("Narrative:")
        lines.append(report["narrative"])

    return "\n".join(lines)
