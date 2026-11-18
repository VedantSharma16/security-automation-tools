"""Assemble the analysis into a report dict and render it as JSON or Markdown."""

from __future__ import annotations

import json
from pathlib import Path

from .detectors import AnalysisContext, Finding
from .iocs import defang, defang_text, extract_iocs
from .scoring import risk_score, severity_breakdown, verdict


def build_report(source: str | Path, ctx: AnalysisContext, findings: list[Finding]) -> dict:
    e = ctx.email
    return {
        "source": str(source),
        "verdict": verdict(findings),
        "risk_score": risk_score(findings),
        "severity_breakdown": severity_breakdown(findings),
        "message": {
            "subject": e.subject,
            "from": e.sender.to_dict(),
            "reply_to": [r.to_dict() for r in e.reply_to],
            "return_path": e.return_path,
            "to": [t.address for t in e.to],
            "date": e.date,
            "message_id": e.message_id,
            "attachments": [a.to_dict() for a in e.attachments],
        },
        "authentication": ctx.auth.to_dict(),
        "originating_ip": ctx.origin_ip,
        "received_chain": [h.to_dict() for h in ctx.hops],
        "link_count": len(ctx.body.links),
        "findings": [f.to_dict() for f in findings],
        "iocs": extract_iocs(ctx),
        "narrative": "",
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(report: dict) -> str:
    m = report["message"]
    a = report["authentication"]
    out = [
        "# Phishing Triage Report",
        "",
        f"**Verdict:** `{report['verdict']}`  |  **Risk score:** {report['risk_score']}/100",
        "",
        "## Message",
        "",
        f"- **Subject:** {_md_escape(m['subject'])}",
        f"- **From:** {_md_escape(m['from']['display_name'])} <{defang(m['from']['address'])}>",
    ]
    if m["reply_to"]:
        out.append(f"- **Reply-To:** {', '.join(defang(r['address']) for r in m['reply_to'])}")
    out += [
        f"- **Return-Path:** {defang(m['return_path']) or '-'}",
        f"- **Date:** {m['date'] or '-'}",
        f"- **Originating IP:** {defang(report['originating_ip']) or 'unknown'}",
        (f"- **Authentication:** SPF `{a['spf']}` · DKIM `{a['dkim']}` · DMARC `{a['dmarc']}`"
        f" (source: {a['source']})"),
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        out.append("_No phishing indicators detected._")
    else:
        out += ["| Severity | Rule | Finding | ATT&CK / ATLAS |", "|---|---|---|---|"]
        for f in report["findings"]:
            out.append(f"| {f['severity']} | `{f['rule']}` | {_md_escape(f['title'])} | {f['technique']} |")
        out += ["", "### Evidence", ""]
        for f in report["findings"]:
            out.append(f"- **{f['rule']}**")
            out += [f"  - `{_md_escape(defang_text(ev))}`" for ev in f["evidence"]]

    if report["received_chain"]:
        out += ["", "## Delivery path (origin first)", "", "| # | From | By | IP | Delay (s) |", "|---|---|---|---|---|"]
        for h in report["received_chain"]:
            delay = "" if h["delay_seconds"] is None else f"{h['delay_seconds']:.0f}"
            out.append(f"| {h['index']} | {_md_escape(h['from_host'])} | {_md_escape(h['by_host'])} | {h['ip']} | {delay} |")

    out += ["", "## IOCs (defanged)", ""]
    any_ioc = False
    for key, values in report["iocs"].items():
        if values:
            any_ioc = True
            out.append(f"- **{key}:** " + ", ".join(f"`{v}`" for v in values))
    if not any_ioc:
        out.append("_None._")

    out += ["", "## Analyst narrative", "", report["narrative"] or "_(not generated)_", ""]
    return "\n".join(out)
