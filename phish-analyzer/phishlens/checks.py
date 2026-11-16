"""Deterministic phishing detectors.

Every check is a pure function ``(ParsedEmail, Intel) -> list[Finding]``.
Findings carry a weight (contribution to the risk score), human-readable
evidence, and where applicable a MITRE ATT&CK technique, so an analyst can
audit exactly *why* a message was flagged.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from importlib import resources
from typing import Callable
from urllib.parse import urlsplit

from .domains import find_lookalike, hostname, is_ip, registrable_domain
from .parser import ParsedEmail

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    id: str
    category: str      # authentication | sender | link | attachment | content
    severity: str
    weight: int
    title: str
    evidence: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Intel:
    protected_domains: list[str]
    brand_keywords: dict[str, str]
    url_shorteners: set[str]
    suspicious_tlds: set[str]
    dangerous_extensions: set[str]
    macro_extensions: set[str]
    archive_extensions: set[str]
    html_extensions: set[str]
    lure_keywords: dict[str, list[str]]

    @classmethod
    def load(cls, extra_protected: list[str] | None = None) -> "Intel":
        data = json.loads(resources.files("phishlens").joinpath("data/intel.json").read_text())
        protected = list(dict.fromkeys(data["protected_domains"] + [d.lower() for d in (extra_protected or [])]))
        return cls(
            protected_domains=protected,
            brand_keywords=data["brand_keywords"],
            url_shorteners=set(data["url_shorteners"]),
            suspicious_tlds=set(data["suspicious_tlds"]),
            dangerous_extensions=set(data["dangerous_extensions"]),
            macro_extensions=set(data["macro_extensions"]),
            archive_extensions=set(data["archive_extensions"]),
            html_extensions=set(data["html_extensions"]),
            lure_keywords=data["lure_keywords"],
        )


# --------------------------------------------------------------------------- #
# Authentication (SPF / DKIM / DMARC)
# --------------------------------------------------------------------------- #

_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)", re.I)


def parse_auth_results(values: list[str]) -> dict[str, str]:
    """Return the first verdict seen for each mechanism, e.g. ``{'spf': 'fail'}``.

    Only the *first* Authentication-Results header is trusted by default: it
    is the one prepended by the receiving MTA. Later ones can be forged by the
    sender, which is itself a common evasion trick.
    """
    out: dict[str, str] = {}
    for value in values[:1]:
        for mech, verdict in _AUTH_RE.findall(value):
            out.setdefault(mech.lower(), verdict.lower())
    return out


def check_authentication(email: ParsedEmail, intel: Intel) -> list[Finding]:
    results = parse_auth_results(email.auth_results)
    if not results:
        return [Finding("auth.missing", "authentication", "low", 5,
                        "No Authentication-Results header present",
                        ["Cannot confirm SPF/DKIM/DMARC; message may not have passed a filtering MTA"])]
    findings = []
    bad = {"fail", "softfail", "permerror", "temperror", "none", "neutral"}
    weights = {"dmarc": 30, "spf": 15, "dkim": 15}
    for mech in ("dmarc", "spf", "dkim"):
        verdict = results.get(mech)
        if verdict in bad:
            hard = verdict in ("fail", "permerror") or (mech == "dmarc" and verdict != "none")
            findings.append(Finding(
                f"auth.{mech}_{verdict}", "authentication",
                "high" if hard else "medium",
                weights[mech] if hard else weights[mech] // 2,
                f"{mech.upper()} {verdict}",
                [f"Authentication-Results: {mech}={verdict}"],
                ["T1566"] if hard else [],
            ))
    return findings


# --------------------------------------------------------------------------- #
# Sender identity
# --------------------------------------------------------------------------- #

_EMAIL_IN_NAME = re.compile(r"[\w.+-]+@([\w-]+\.[\w.-]+)")


def check_sender(email: ParsedEmail, intel: Intel) -> list[Finding]:
    findings: list[Finding] = []
    from_dom = email.sender.domain
    from_reg = registrable_domain(from_dom)

    for rt in email.reply_to:
        if rt.domain and registrable_domain(rt.domain) != from_reg:
            findings.append(Finding(
                "sender.reply_to_mismatch", "sender", "medium", 15,
                "Reply-To domain differs from From domain",
                [f"From: {email.sender.email}", f"Reply-To: {rt.email}"],
                ["T1656"],
            ))
            break

    if email.return_path and "@" in email.return_path:
        rp_reg = registrable_domain(email.return_path.rpartition("@")[2])
        if rp_reg and rp_reg != from_reg:
            findings.append(Finding(
                "sender.return_path_mismatch", "sender", "low", 5,
                "Return-Path (envelope sender) differs from From domain",
                [f"From: {email.sender.email}", f"Return-Path: {email.return_path}"],
            ))

    name = email.sender.display_name
    m = _EMAIL_IN_NAME.search(name)
    if m and registrable_domain(m.group(1).lower()) != from_reg:
        findings.append(Finding(
            "sender.display_name_spoof", "sender", "high", 25,
            "Display name contains a different email address",
            [f"From: \"{name}\" <{email.sender.email}>"],
            ["T1656", "T1036"],
        ))

    lowered = name.lower()
    for brand, legit in intel.brand_keywords.items():
        if re.search(rf"\b{re.escape(brand)}\b", lowered) and from_reg != registrable_domain(legit):
            findings.append(Finding(
                "sender.brand_impersonation", "sender", "high", 20,
                f"Display name claims '{brand}' but sender domain is not {legit}",
                [f"From: \"{name}\" <{email.sender.email}>"],
                ["T1656"],
            ))
            break

    lk = find_lookalike(from_dom, intel.protected_domains)
    if lk:
        findings.append(Finding(
            "sender.lookalike_domain", "sender", "critical", 35,
            f"Sender domain imitates {lk.impersonates} ({lk.technique})",
            [f"From domain: {from_dom}", lk.detail],
            ["T1583.001", "T1656"],
        ))

    mid = email.message_id.strip("<>")
    if "@" in mid and from_reg:
        mid_reg = registrable_domain(mid.rpartition("@")[2].lower())
        if mid_reg and mid_reg != from_reg and not _is_major_esp(mid_reg):
            findings.append(Finding(
                "sender.message_id_mismatch", "sender", "info", 2,
                "Message-ID domain differs from From domain",
                [f"Message-ID: {email.message_id}"],
            ))
    return findings


_ESP = {"google.com", "gmail.com", "outlook.com", "prod.outlook.com", "amazonses.com",
        "sendgrid.net", "mailgun.org", "mcsv.net", "mailchimp.com", "sparkpostmail.com"}


def _is_major_esp(reg: str) -> bool:
    return reg in _ESP


# --------------------------------------------------------------------------- #
# Links
# --------------------------------------------------------------------------- #

_CRED_PATH = re.compile(r"(?i)(login|signin|sign-in|verify|account|secure|update|password|auth|wp-admin|webscr)")
_SCHEME = re.compile(r"(?i)^\s*(https?|mailto|tel|cid|javascript|data|vbscript|ftp|file):")
_FILE_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "zip", "png", "jpg", "html", "htm", "csv", "exe"}
_DOMAINISH = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)


def check_links(email: ParsedEmail, intel: Intel) -> list[Finding]:
    findings: list[Finding] = []
    reported_lookalikes: set[str] = set()

    for link in email.links:
        url = link.url
        m = _SCHEME.match(url)
        scheme = m.group(1).lower() if m else ("http" if "://" not in url else urlsplit(url).scheme.lower())
        if scheme in ("mailto", "tel", "cid"):
            continue
        if scheme in ("javascript", "data", "vbscript"):
            findings.append(Finding("link.script_scheme", "link", "high", 25,
                                    f"Link uses dangerous '{scheme}:' scheme", [url[:120]], ["T1566.002"]))
            continue
        host = hostname(url)
        if not host:
            continue
        reg = registrable_domain(host)
        ev = f"{url[:150]}" + (f"  (text: \"{link.text[:60]}\")" if link.text else "")

        if is_ip(host):
            findings.append(Finding("link.ip_literal", "link", "high", 20,
                                    "Link points directly at an IP address", [ev], ["T1566.002"]))

        if "@" in (urlsplit(url).netloc if "://" in url else ""):
            findings.append(Finding("link.userinfo_obfuscation", "link", "high", 20,
                                    "URL contains '@' userinfo to disguise the real host", [ev], ["T1566.002"]))

        if reg in intel.url_shorteners:
            findings.append(Finding("link.shortener", "link", "low", 8,
                                    "Link uses a URL shortener that hides the destination", [ev], ["T1566.002"]))

        tld = host.rsplit(".", 1)[-1]
        if tld in intel.suspicious_tlds:
            findings.append(Finding("link.suspicious_tld", "link", "low", 8,
                                    f"Link uses high-abuse TLD '.{tld}'", [ev]))

        if "xn--" in host:
            findings.append(Finding("link.punycode", "link", "medium", 12,
                                    "Link hostname is internationalised (punycode)", [ev], ["T1566.002"]))

        lk = find_lookalike(host, intel.protected_domains)
        if lk and reg not in reported_lookalikes:
            reported_lookalikes.add(reg)
            findings.append(Finding("link.lookalike_domain", "link", "critical", 35,
                                    f"Link domain imitates {lk.impersonates} ({lk.technique})",
                                    [ev, lk.detail], ["T1566.002", "T1583.001"]))

        # Visible text says one domain, href goes to another.
        if link.source == "html" and link.text:
            shown = _DOMAINISH.search(link.text)
            if shown and shown.group(1).rsplit(".", 1)[-1].lower() not in _FILE_EXTS:
                shown_reg = registrable_domain(shown.group(1).lower())
                if shown_reg and reg and shown_reg != reg and "." in shown_reg:
                    findings.append(Finding("link.text_href_mismatch", "link", "high", 25,
                                            "Link text shows a different domain than its real target",
                                            [f"shows '{shown.group(1)}' but goes to '{host}'"], ["T1566.002"]))

        if scheme == "http" and _CRED_PATH.search(url):
            findings.append(Finding("link.cleartext_credential_path", "link", "medium", 10,
                                    "Unencrypted link to a login/verification-style path", [ev], ["T1566.002"]))

    return _merge_duplicates(findings)


def _merge_duplicates(findings: list[Finding]) -> list[Finding]:
    """Collapse repeated findings of the same id into one with combined evidence."""
    merged: dict[str, Finding] = {}
    for f in findings:
        if f.id in merged:
            for e in f.evidence:
                if e not in merged[f.id].evidence:
                    merged[f.id].evidence.append(e)
        else:
            merged[f.id] = f
    return list(merged.values())


# --------------------------------------------------------------------------- #
# Attachments
# --------------------------------------------------------------------------- #

_MAGIC = {
    b"MZ": "Windows PE executable",
    b"PK\x03\x04": "ZIP container (zip/docx/xlsx/jar)",
    b"%PDF": "PDF document",
    b"\xd0\xcf\x11\xe0": "OLE2 compound file (legacy Office, may contain macros)",
    b"Rar!": "RAR archive",
    b"7z\xbc\xaf": "7-Zip archive",
}
_EXT_EXPECTED_MAGIC = {"pdf": b"%PDF", "docx": b"PK\x03\x04", "xlsx": b"PK\x03\x04", "zip": b"PK\x03\x04"}


def _magic(head: bytes) -> tuple[bytes, str] | None:
    for sig, desc in _MAGIC.items():
        if head.startswith(sig):
            return sig, desc
    return None


def check_attachments(email: ParsedEmail, intel: Intel) -> list[Finding]:
    findings: list[Finding] = []
    body_l = email.body.lower()
    for att in email.attachments:
        name = att.filename.strip().lower()
        parts = name.rsplit(".", 2)
        ext = parts[-1] if len(parts) > 1 else ""
        ev = f"{att.filename} ({att.content_type}, {att.size} bytes, sha256 {att.sha256[:16]}...)"

        if len(parts) == 3 and ext in intel.dangerous_extensions and parts[-2] in (
            "pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "zip"
        ):
            findings.append(Finding("attachment.double_extension", "attachment", "critical", 40,
                                    "Attachment hides an executable behind a double extension",
                                    [ev], ["T1566.001", "T1036.007"]))
        elif ext in intel.dangerous_extensions:
            findings.append(Finding("attachment.dangerous_type", "attachment", "critical", 35,
                                    f"Executable/script attachment type '.{ext}'", [ev], ["T1566.001", "T1204.002"]))

        if ext in intel.macro_extensions:
            findings.append(Finding("attachment.macro_enabled", "attachment", "high", 25,
                                    f"Macro-enabled Office document '.{ext}'", [ev], ["T1566.001", "T1204.002"]))

        if ext in intel.html_extensions:
            findings.append(Finding("attachment.html_smuggling", "attachment", "high", 25,
                                    "HTML/SVG attachment (common credential-harvest / HTML smuggling vector)",
                                    [ev], ["T1566.001", "T1027.006"]))

        if ext in intel.archive_extensions and re.search(r"\b(password|passcode|pwd)\b", body_l):
            findings.append(Finding("attachment.encrypted_archive_lure", "attachment", "high", 20,
                                    "Archive attachment with a password supplied in the body (evades AV scanning)",
                                    [ev], ["T1566.001", "T1027"]))

        magic = _magic(att.head)
        if magic and magic[0] == b"MZ" and ext not in ("exe", "dll", "scr", "com", "cpl"):
            findings.append(Finding("attachment.magic_mismatch", "attachment", "critical", 40,
                                    f"File named '.{ext}' is actually a {magic[1]}", [ev], ["T1036.008"]))
        elif ext in _EXT_EXPECTED_MAGIC and att.size and not att.head.startswith(_EXT_EXPECTED_MAGIC[ext]):
            findings.append(Finding("attachment.magic_mismatch", "attachment", "high", 20,
                                    f"File content does not match its '.{ext}' extension"
                                    + (f" (looks like {magic[1]})" if magic else ""), [ev], ["T1036.008"]))
    return findings


# --------------------------------------------------------------------------- #
# Content / social engineering
# --------------------------------------------------------------------------- #

_LURE_META = {
    "credential": ("content.credential_lure", "medium", 15, "Credential-harvesting language", ["T1598.003"]),
    "urgency": ("content.urgency", "low", 8, "Urgency / pressure language", []),
    "financial": ("content.financial_request", "medium", 15, "Payment / banking request language (BEC indicator)", ["T1534"]),
    "secrecy": ("content.secrecy", "low", 8, "Secrecy or availability probing (BEC / gift-card scam pattern)", []),
}


def check_content(email: ParsedEmail, intel: Intel) -> list[Finding]:
    text = f"{email.subject}\n{email.body}".lower()
    findings = []
    for category, phrases in intel.lure_keywords.items():
        hits = [p for p in phrases if p in text]
        if not hits or category not in _LURE_META:
            continue
        fid, sev, weight, title, mitre = _LURE_META[category]
        # Diminishing extra weight for multiple distinct phrases, capped.
        weight = min(weight + 3 * (len(hits) - 1), weight * 2)
        findings.append(Finding(fid, "content", sev, weight, title, [f'"{h}"' for h in hits[:6]], mitre))

    if any(link.text == "<form action>" for link in email.links):
        findings.append(Finding("content.embedded_form", "content", "high", 25,
                                "Email body contains an HTML form that submits data off-message",
                                [l.url for l in email.links if l.text == "<form action>"][:3], ["T1598.003"]))
    return findings


ALL_CHECKS: list[Callable[[ParsedEmail, Intel], list[Finding]]] = [
    check_authentication,
    check_sender,
    check_links,
    check_attachments,
    check_content,
]


def run_checks(email: ParsedEmail, intel: Intel) -> list[Finding]:
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(email, intel))
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (-order[f.severity], -f.weight, f.id))
    return findings
