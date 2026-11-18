"""Extract shareable indicators of compromise, defanged for safe pasting."""

from __future__ import annotations

import re

from .detectors import AnalysisContext
from .domains import DEFAULT_PROTECTED_BRANDS, registrable_domain


def defang(value: str) -> str:
    return (
        value.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace(".", "[.]")
        .replace("@", "[@]")
    )


_URL_OR_EMAIL_RE = re.compile(r"https?://[^\s'\"<>]+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.IGNORECASE)


def defang_text(text: str) -> str:
    """Defang every URL and email address embedded in free text, leaving the rest readable."""
    return _URL_OR_EMAIL_RE.sub(lambda m: defang(m.group(0)), text)


def extract_iocs(ctx: AnalysisContext, defanged: bool = True) -> dict[str, list[str]]:
    # Never emit a protected brand's real domain as an IOC: phishing mails often
    # quote the genuine URL as decoy text, and blocking it would break things.
    legit = {d for ds in (ctx.brands or DEFAULT_PROTECTED_BRANDS).values() for d in ds}
    urls = sorted(
        {link.url for link in ctx.body.links if registrable_domain(link.host) not in legit}
        | {a for a in ctx.body.form_actions if a.lower().startswith(("http://", "https://"))}
    )
    domains = sorted({registrable_domain(link.host) for link in ctx.body.links if link.host} - legit)
    sender_domains = {ctx.email.sender.domain} | {r.domain for r in ctx.email.reply_to}
    if ctx.email.return_path_domain:
        sender_domains.add(ctx.email.return_path_domain)
    emails = sorted({ctx.email.sender.address, *(r.address for r in ctx.email.reply_to)} - {""})
    iocs = {
        "urls": urls,
        "domains": sorted(set(domains) | {registrable_domain(d) for d in sender_domains if d} - legit),
        "ips": [ctx.origin_ip] if ctx.origin_ip else [],
        "email_addresses": emails,
        "sha256": sorted({a.sha256 for a in ctx.email.attachments}),
        "md5": sorted({a.md5 for a in ctx.email.attachments}),
    }
    if defanged:
        for key in ("urls", "domains", "ips", "email_addresses"):
            iocs[key] = [defang(v) for v in iocs[key]]
    return iocs
