"""Assemble a parsed email, its auth-results verdict, and rule findings into
a structured report (JSON- and LLM-prompt-friendly), plus a human-readable
Markdown rendering for terminal / ticket use.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .authresults import AuthResultsSummary
from .heuristics import Finding
from .iocs import defang_ip, defang_url, extract_ips, extract_urls
from .parser import ParsedEmail
from .scoring import build_summary


def _defanged_iocs(email: ParsedEmail) -> dict:
    urls = extract_urls(email.body_text) + extract_urls(email.body_html)
    urls += [link.href for link in email.html_links if link.href.lower().startswith(("http://", "https://"))]
    unique_urls = list(dict.fromkeys(urls))

    ips: list[str] = []
    for header in email.received_headers:
        ips.extend(extract_ips(header))
    unique_ips = list(dict.fromkeys(ips))

    return {
        "urls": [defang_url(u) for u in unique_urls],
        "ips": [defang_ip(ip) for ip in unique_ips],
        "attachment_hashes": [
            {"filename": a.filename, "sha256": a.sha256, "size": a.size} for a in email.attachments
        ],
    }


def build_report(email: ParsedEmail, auth: AuthResultsSummary, findings: list[Finding]) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "message": {
            "subject": email.subject,
            "date": email.date_raw,
            "message_id": email.message_id,
            "from_display_name": email.from_display_name,
            "from_addr": email.from_addr,
            "from_domain": email.from_domain,
            "reply_to_addr": email.reply_to_addr,
            "return_path_addr": email.return_path_addr,
        },
        "auth_results": {
            "evaluated": auth.evaluated,
            "spf": auth.spf,
            "dkim": auth.dkim,
            "dmarc": auth.dmarc,
        },
        "iocs": _defanged_iocs(email),
        "findings": [f.to_dict() for f in findings],
        "summary": build_summary(findings),
        "narrative": None,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def to_markdown(report: dict) -> str:
    lines: list[str] = []
    msg = report["message"]
    lines.append(f"# Phishing Triage Report: {msg['subject'] or '(no subject)'}")
    lines.append("")
    lines.append(f"Generated: {report['generated_at']}")
    lines.append(f"From: {msg['from_display_name']} <{msg['from_addr']}> (domain: {msg['from_domain']})")
    if msg["reply_to_addr"]:
        lines.append(f"Reply-To: {msg['reply_to_addr']}")
    if msg["date"]:
        lines.append(f"Date: {msg['date']}")
    lines.append("")

    auth = report["auth_results"]
    lines.append("## Authentication")
    lines.append("")
    if auth["evaluated"]:
        lines.append(f"- SPF: {auth['spf']}")
        lines.append(f"- DKIM: {auth['dkim']}")
        lines.append(f"- DMARC: {auth['dmarc']}")
    else:
        lines.append("- No Authentication-Results header present")
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
            lines.append(f["detail"])
            if f["evidence"]:
                lines.append("")
                lines.append(f"- Evidence: `{json.dumps(f['evidence'])}`")
            lines.append("")
    else:
        lines.append("No phishing indicators detected by the rule engine.")
        lines.append("")

    iocs = report["iocs"]
    if iocs["urls"] or iocs["ips"] or iocs["attachment_hashes"]:
        lines.append("## Extracted IOCs (defanged)")
        lines.append("")
        for url in iocs["urls"]:
            lines.append(f"- URL: `{url}`")
        for ip in iocs["ips"]:
            lines.append(f"- IP: `{ip}`")
        for att in iocs["attachment_hashes"]:
            lines.append(f"- Attachment: `{att['filename']}` sha256=`{att['sha256']}` ({att['size']} bytes)")
        lines.append("")

    if report.get("narrative"):
        lines.append("## Analyst Narrative")
        lines.append("")
        lines.append(report["narrative"])
        lines.append("")

    return "\n".join(lines)
