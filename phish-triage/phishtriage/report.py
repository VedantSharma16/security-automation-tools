"""Assemble a triage report (dict) and render it as JSON, Markdown, or a CSV IOC list."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
from urllib.parse import urlsplit

from .checks import Finding
from .parser import ParsedEmail
from .scoring import Score
from .urls import normalize_host, registrable_domain


def defang(value: str) -> str:
    """Make an indicator non-clickable for safe sharing in tickets and chat."""
    return (value.replace("https://", "hxxps://").replace("http://", "hxxp://")
            .replace(".", "[.]").replace("@", "[@]"))


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
                   "100.64.0.0/10")]


def _public_ip(ip: str | None) -> str | None:
    """Return ``ip`` unless it is internal (RFC1918, loopback, link-local, CGNAT)."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return None if any(addr in net for net in _INTERNAL_NETS) else ip


def _ascii(domain: str) -> str:
    """Punycode form - what DNS, proxies and blocklists actually match on."""
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


def extract_iocs(email: ParsedEmail) -> dict:
    urls, domains = [], []
    for link in email.links:
        if not link.href.lower().startswith(("http://", "https://")):
            continue
        if link.href not in urls:
            urls.append(link.href)
        host = normalize_host(urlsplit(link.href).hostname or "")
        if host:
            reg = _ascii(registrable_domain(host))
            if reg not in domains:
                domains.append(reg)
    senders = [a for a in (email.from_address, email.reply_to, email.return_path) if a]
    return {
        "sender_addresses": list(dict.fromkeys(senders)),
        "originating_ip": _public_ip(email.originating_ip),
        "urls": urls,
        "domains": domains,
        "attachments": [a.to_dict() for a in email.attachments],
    }


def recommended_actions(verdict: str, findings: list[Finding]) -> list[str]:
    if verdict == "clean":
        return ["No action required. Release to user if quarantined."]
    cats = {f.category for f in findings}
    rules = {f.rule_id for f in findings}
    actions = [
        "Search the mail gateway for other recipients of this message (same sender, subject, or URLs) "
        "and purge from all mailboxes.",
    ]
    if verdict == "malicious":
        actions.append("Block sender address/domain and listed URL domains at the email gateway and web proxy.")
    if "url" in cats:
        actions.append("Check proxy/DNS logs for any user who visited the listed URLs; "
                       "if credentials were entered, force a password reset and revoke active sessions/MFA tokens.")
    if "attachment" in cats:
        actions.append("Submit attachment hashes to EDR / sandbox; hunt for the hashes across endpoints "
                       "and isolate any host where the file executed.")
    if "CNT-BEC" in rules or "HDR-REPLYTO" in rules:
        actions.append("Verify any payment or banking change out-of-band (phone a known contact); "
                       "alert finance/AP team to the lure.")
    if "CNT-PROMPT-INJECTION" in rules:
        actions.append("Message contains instructions aimed at AI assistants - ensure no AI mail agent "
                       "acted on it (sent replies, forwarded data, changed rules).")
    actions.append("Notify the reporting user of the outcome and log the case with the IOCs from this report.")
    return actions


def build_report(source: str, email: ParsedEmail, findings: list[Finding], result: Score) -> dict:
    return {
        "source": source,
        "message": {
            "subject": email.subject,
            "from": f"{email.from_name} <{email.from_address}>" if email.from_name else email.from_address,
            "reply_to": email.reply_to,
            "return_path": email.return_path,
            "to": email.to,
            "date": email.date,
            "message_id": email.message_id,
            "received_hops": len(email.received),
        },
        "authentication": email.auth.to_dict(),
        "summary": result.to_dict() | {"total_findings": len(findings)},
        "findings": [f.to_dict() for f in findings],
        "iocs": extract_iocs(email),
        "recommended_actions": recommended_actions(result.verdict, findings),
    }


def to_json(report: dict | list[dict]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


_BADGE = {"malicious": "🔴 MALICIOUS", "suspicious": "🟠 SUSPICIOUS", "clean": "🟢 CLEAN"}


def to_markdown(report: dict) -> str:
    s = report["summary"]
    m = report["message"]
    auth = report["authentication"]
    lines = [
        f"# Phishing triage: {m['subject'] or '(no subject)'}",
        "",
        f"**Verdict:** {_BADGE[s['verdict']]} &nbsp; **Risk score:** {s['risk_score']}/100 "
        f"&nbsp; **Findings:** {s['total_findings']} (highest: {s['highest_severity']})",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| From | `{m['from']}` |",
        f"| Reply-To | `{m['reply_to'] or '-'}` |",
        f"| Return-Path | `{m['return_path'] or '-'}` |",
        f"| Date | {m['date'] or '-'} |",
        f"| SPF / DKIM / DMARC | {auth['spf'] or '-'} / {auth['dkim'] or '-'} / {auth['dmarc'] or '-'} |",
        f"| Source file | `{report['source']}` |",
        "",
    ]
    if report.get("narrative"):
        lines += ["## Analyst summary", "", report["narrative"], ""]

    lines += ["## Findings", ""]
    if report["findings"]:
        lines += ["| Severity | Rule | Finding | Evidence | ATT&CK |", "|---|---|---|---|---|"]
        for f in report["findings"]:
            evidence = defang(f["evidence"]).replace("|", "\\|")
            lines.append(f"| {f['severity'].upper()} | {f['rule_id']} | {f['title']} | {evidence} | "
                         f"{f['mitre'] or '-'} |")
    else:
        lines.append("_No findings._")

    iocs = report["iocs"]
    lines += ["", "## Indicators of compromise (defanged)", ""]
    for addr in iocs["sender_addresses"]:
        lines.append(f"- sender: `{defang(addr)}`")
    if iocs["originating_ip"]:
        lines.append(f"- originating IP: `{defang(iocs['originating_ip'])}`")
    for d in iocs["domains"]:
        lines.append(f"- domain: `{defang(d)}`")
    for u in iocs["urls"]:
        lines.append(f"- url: `{defang(u)}`")
    for a in iocs["attachments"]:
        lines.append(f"- file: `{a['filename']}` sha256 `{a['sha256']}`")

    lines += ["", "## Recommended actions", ""]
    lines += [f"{i}. {a}" for i, a in enumerate(report["recommended_actions"], 1)]
    return "\n".join(lines) + "\n"


def iocs_to_csv(reports: list[dict]) -> str:
    """Flatten IOCs from one or more reports into ``type,value,verdict,source`` rows (not defanged)."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["type", "value", "verdict", "source"])
    for r in reports:
        verdict, src, iocs = r["summary"]["verdict"], r["source"], r["iocs"]
        for addr in iocs["sender_addresses"]:
            writer.writerow(["email", addr, verdict, src])
        if iocs["originating_ip"]:
            writer.writerow(["ipv4", iocs["originating_ip"], verdict, src])
        for d in iocs["domains"]:
            writer.writerow(["domain", d, verdict, src])
        for u in iocs["urls"]:
            writer.writerow(["url", u, verdict, src])
        for a in iocs["attachments"]:
            writer.writerow(["sha256", a["sha256"], verdict, src])
    return buf.getvalue()
