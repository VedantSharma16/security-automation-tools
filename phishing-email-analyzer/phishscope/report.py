"""Build the triage report: verdict, findings, IOCs, and response actions.

IOCs are emitted twice: raw in JSON (for SIEM / blocklist automation) and
defanged in Markdown (safe to paste into tickets and chat without creating
clickable malicious links).
"""

from __future__ import annotations

import json
import re
from ipaddress import ip_address, ip_network

from .checks import AnalysisConfig, Finding, normalize_url, run_all_checks, sender_is_trusted
from .domains import is_legitimate, load_intel, registrable_domain
from .parser import ParsedEmail, domain_of
from .scoring import score_findings

# Infrastructure that is never a useful sender IOC. Documentation ranges
# (RFC 5737) are intentionally *not* excluded so they can be used in fixtures.
NON_ROUTABLE = [ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10",
)]

_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")

RECOMMENDED_ACTIONS = {
    "malicious": [
        "Quarantine this message and purge matching copies tenant-wide (search by sender, subject, and URL/hash IOCs).",
        "Block the sender domain, URLs, and attachment hashes at the mail gateway, proxy, and EDR.",
        "Identify recipients who clicked or opened attachments (proxy/EDR logs); reset credentials and revoke sessions for any who did.",
        "Open an incident ticket and attach this report.",
    ],
    "likely_phishing": [
        "Quarantine the message pending analyst review.",
        "Detonate URLs/attachments in a sandbox and check IOCs against threat intelligence.",
        "Search the mailbox estate for the same sender or URLs.",
    ],
    "suspicious": [
        "Hold for analyst review; verify with the purported sender via a known-good channel.",
        "Do not click links or open attachments until reviewed.",
    ],
    "clean": ["No action required. Release to the user if it was reported."],
}


def originating_ips(email: ParsedEmail) -> list[str]:
    """Public IPs from the Received chain, oldest hop first."""
    ips: list[str] = []
    for header in reversed(email.received):
        for candidate in _IP_RE.findall(header):
            try:
                ip = ip_address(candidate)
            except ValueError:
                continue
            if not any(ip in net for net in NON_ROUTABLE) and candidate not in ips:
                ips.append(candidate)
    return ips


def _is_ip(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def extract_iocs(email: ParsedEmail, cfg: AnalysisConfig) -> dict:
    """Blockable indicators. Legitimate protected domains are excluded, and
    shorteners are kept as URLs but not as domains (blocking bit.ly outright
    is rarely what a responder wants)."""
    shorteners = set(load_intel()["url_shorteners"])
    urls, domains, ips = set(), set(), set()
    for link in email.links:
        url = normalize_url(link.url)
        if not url.lower().startswith("http"):
            continue
        host = re.sub(r"(?i)^https?://(?:[^@/]*@)?", "", url).split("/")[0].split(":")[0].lower()
        if not host or is_legitimate(host, cfg.protected_domains):
            continue
        urls.add(url)
        if _is_ip(host):
            ips.add(host)
        elif registrable_domain(host) not in shorteners:
            domains.add(host)
    for addr in [email.from_address, *email.reply_to, email.return_path]:
        d = domain_of(addr)
        if d and not is_legitimate(d, cfg.protected_domains) and d not in load_intel()["free_mail_domains"]:
            domains.add(d)
    return {
        "sender": email.from_address,
        "reply_to": email.reply_to,
        "return_path": email.return_path,
        "originating_ips": originating_ips(email),
        "url_ips": sorted(ips),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "attachments": [
            {"filename": a.filename, "sha256": a.sha256, "size": a.size} for a in email.attachments
        ],
    }


def analyze(email: ParsedEmail, cfg: AnalysisConfig | None = None, source: str = "") -> dict:
    cfg = cfg or AnalysisConfig()
    findings: list[Finding] = run_all_checks(email, cfg)
    summary = score_findings(findings, trusted_sender=sender_is_trusted(email, cfg))
    return {
        "source": source,
        "message": {
            "subject": email.subject,
            "from": f"{email.from_display} <{email.from_address}>".strip(),
            "to": email.to,
            "date": email.date,
            "message_id": email.message_id,
            "authentication": {
                "spf": email.auth.spf, "dkim": email.auth.dkim, "dmarc": email.auth.dmarc,
            },
            "link_count": len(email.links),
            "attachment_count": len(email.attachments),
        },
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
        "iocs": extract_iocs(email, cfg),
        "recommended_actions": RECOMMENDED_ACTIONS[summary["verdict"]],
    }


def defang(value: str) -> str:
    """Defang a single indicator (URL, domain, IP, or address)."""
    value = re.sub(r"(?i)^http", "hxxp", value)
    return value.replace(".", "[.]").replace("@", "[@]")


# Hostnames (alphabetic final label) and dotted-quad IPs. The look-behind skips
# tokens glued to '_' or '.', so filenames and ATT&CK IDs (T1566.001) are untouched.
_HOSTLIKE = re.compile(
    r"(?i)(?<![\w.-])(?:(?:[a-z0-9-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?![\w-])"
)


def defang_text(text: str) -> str:
    """Defang every URL scheme, host, IP, and address embedded in free text."""
    text = re.sub(r"(?i)\bhttp(s?)://", r"hxxp\1://", text)
    text = _HOSTLIKE.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    return re.sub(r"(?<=\w)@(?=[\w-]+\[\.\])", "[@]", text)


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def to_markdown(report: dict) -> str:
    s, m, iocs = report["summary"], report["message"], report["iocs"]
    verdict = s["verdict"].replace("_", " ").upper()
    lines = [
        f"# Phishing Triage Report: {verdict} ({s['risk_score']}/100)",
        "",
        f"- **Subject:** {m['subject']}",
        f"- **From:** {defang_text(m['from'])}",
        f"- **Date:** {m['date']}",
        f"- **Auth:** SPF={m['authentication']['spf']} · DKIM={m['authentication']['dkim']}"
        f" · DMARC={m['authentication']['dmarc']}",
        f"- **Findings:** {s['total_findings']} (highest severity: {s['highest_severity']})",
        "",
    ]
    if report.get("narrative"):
        lines += ["## Analyst Summary", "", defang_text(report["narrative"].strip()), ""]

    lines += ["## Findings", ""]
    if not report["findings"]:
        lines.append("_No phishing indicators detected._")
    for f in report["findings"]:
        lines.append(f"### [{f['severity'].upper()}] {f['title']} (+{f['score']}, {f['mitre']})")
        lines += [f"- {defang_text(e)}" for e in f["evidence"]]
        lines.append("")

    lines += ["## Indicators of Compromise (defanged)", ""]
    if iocs["originating_ips"]:
        lines.append(f"- **Originating IPs:** {', '.join(defang(i) for i in iocs['originating_ips'])}")
    if iocs["url_ips"]:
        lines.append(f"- **IPs in links:** {', '.join(defang(i) for i in iocs['url_ips'])}")
    if iocs["domains"]:
        lines.append(f"- **Domains:** {', '.join(defang(d) for d in iocs['domains'])}")
    for url in iocs["urls"]:
        lines.append(f"- **URL:** `{defang(url)}`")
    for att in iocs["attachments"]:
        lines.append(f"- **Attachment:** {att['filename']}: sha256 `{att['sha256']}`")
    lines += ["", "## Recommended Actions", ""]
    lines += [f"{i}. {a}" for i, a in enumerate(report["recommended_actions"], 1)]
    return "\n".join(lines) + "\n"
