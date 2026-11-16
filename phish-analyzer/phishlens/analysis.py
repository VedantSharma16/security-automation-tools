"""Tie parsing, detection, scoring and IOC extraction into one report dict."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from . import __version__
from .checks import Finding, Intel, parse_auth_results, run_checks
from .domains import hostname, is_ip, registrable_domain
from .parser import ParsedEmail

# Verdict bands on the 0-100 risk score.
VERDICTS = ((70, "malicious"), (40, "likely_phishing"), (15, "suspicious"), (0, "clean"))

# Combinations that are far more damning together than apart.
_COMBOS = (
    ({"auth.dmarc_fail", "sender.lookalike_domain"}, 10, "DMARC failure on a lookalike sender domain"),
    ({"link.lookalike_domain", "content.credential_lure"}, 15, "Credential lure pointing at a lookalike domain"),
    ({"link.text_href_mismatch", "content.credential_lure"}, 10, "Credential lure behind a deceptive link"),
    ({"sender.reply_to_mismatch", "content.financial_request"}, 15, "Payment request with replies diverted elsewhere (BEC)"),
)


def score(findings: list[Finding]) -> tuple[int, list[str]]:
    """Sum finding weights plus combo bonuses, capped at 100."""
    ids = {f.id for f in findings}
    total = sum(f.weight for f in findings)
    combos = []
    for required, bonus, label in _COMBOS:
        if required <= ids:
            total += bonus
            combos.append(label)
    return min(total, 100), combos


def verdict_for(risk: int) -> str:
    for threshold, name in VERDICTS:
        if risk >= threshold:
            return name
    return "clean"


def defang(value: str) -> str:
    return value.replace("http", "hxxp", 1).replace(".", "[.]")


def extract_iocs(email: ParsedEmail) -> dict:
    urls = sorted({l.url for l in email.links if l.url.lower().startswith(("http", "www.", "//"))})
    domains = sorted({registrable_domain(h) for h in (hostname(u) for u in urls) if h and not is_ip(h)})
    ips = set(hostname(u) for u in urls if is_ip(hostname(u)))
    for hop in email.received:
        if hop.ip:
            try:
                if _is_public(hop.ip):
                    ips.add(hop.ip)
            except ValueError:
                pass
    return {
        "sender": email.sender.email,
        "sender_domain": email.sender.domain,
        "reply_to": [a.email for a in email.reply_to],
        "urls": urls,
        "domains": domains,
        "ips": sorted(ips),
        "attachments": [
            {"filename": a.filename, "sha256": a.sha256, "md5": a.md5, "size": a.size}
            for a in email.attachments
        ],
    }


_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _is_public(ip: str) -> bool:
    """Externally routable address. Unlike ``is_global`` this keeps the RFC 5737
    documentation ranges, so the sample fixtures behave like real traffic."""
    addr = ipaddress.ip_address(ip)
    if any(addr in n for n in _DOC_NETS):
        return True
    return addr.is_global


def originating_ip(email: ParsedEmail) -> str:
    """The earliest public IP in the Received chain (bottom-most header)."""
    for hop in reversed(email.received):
        if hop.ip:
            try:
                if _is_public(hop.ip):
                    return hop.ip
            except ValueError:
                continue
    return ""


_ACTIONS = {
    "malicious": [
        "Quarantine / purge this message from all mailboxes (search by sender, subject and URL IOCs).",
        "Block listed sender domain, URLs/domains and attachment hashes at the mail gateway, proxy and EDR.",
        "Identify recipients who clicked or opened attachments; reset credentials and review sign-in logs.",
    ],
    "likely_phishing": [
        "Quarantine the message and block the listed domains/URLs at the mail gateway and web proxy.",
        "Check proxy/DNS logs for any user visits to the extracted domains.",
    ],
    "suspicious": [
        "Hold for analyst review; detonate URLs/attachments in a sandbox before releasing.",
    ],
    "clean": ["No action required; release to recipient."],
}


def analyze(email: ParsedEmail, intel: Intel | None = None, source: str = "") -> dict:
    intel = intel or Intel.load()
    findings = run_checks(email, intel)
    risk, combos = score(findings)
    verdict = verdict_for(risk)
    mitre = sorted({t for f in findings for t in f.mitre})
    return {
        "tool": f"phishlens {__version__}",
        "analyzed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
        "message": {
            "subject": email.subject,
            "from": f"{email.sender.display_name} <{email.sender.email}>".strip(),
            "reply_to": [a.email for a in email.reply_to],
            "return_path": email.return_path,
            "to": [a.email for a in email.to],
            "date": email.date,
            "message_id": email.message_id,
            "authentication": parse_auth_results(email.auth_results),
            "received_hops": len(email.received),
            "originating_ip": originating_ip(email),
            "link_count": len(email.links),
            "attachment_count": len(email.attachments),
        },
        "summary": {
            "verdict": verdict,
            "risk_score": risk,
            "finding_count": len(findings),
            "highest_severity": findings[0].severity if findings else "none",
            "combos": combos,
            "mitre_techniques": mitre,
        },
        "findings": [f.to_dict() for f in findings],
        "iocs": extract_iocs(email),
        "recommended_actions": _ACTIONS[verdict],
    }
