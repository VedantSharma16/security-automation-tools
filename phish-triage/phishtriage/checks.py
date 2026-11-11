"""Detection rules. Each check takes a ParsedEmail and returns zero or more Findings.

Rules are grouped by what an analyst would look at during manual triage:
sender authentication/headers, links, attachments, and message content.
Every finding carries the evidence that triggered it plus a MITRE ATT&CK
technique so results can feed straight into a case-management system.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from dataclasses import asdict, dataclass
from functools import lru_cache
from importlib import resources
from typing import Callable

from .parser import Attachment, ParsedEmail
from .urls import analyze_url, find_lookalike, registrable_domain

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    rule_id: str
    category: str  # header | url | attachment | content
    severity: str
    title: str
    evidence: str
    mitre: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@lru_cache(maxsize=1)
def reference() -> dict:
    data = json.loads(resources.files("phishtriage.data").joinpath("reference.json").read_text("utf-8"))
    return {
        "brands": data["brands"],
        "freemail": set(data["freemail_domains"]),
        "shorteners": set(data["url_shorteners"]),
        "suspicious_tlds": set(data["suspicious_tlds"]),
        "dangerous_ext": set(data["dangerous_extensions"]),
        "macro_ext": set(data["macro_extensions"]),
        "archive_ext": set(data["archive_extensions"]),
    }


# --------------------------------------------------------------------------- headers

def check_authentication(email: ParsedEmail) -> list[Finding]:
    findings = []
    auth = email.auth
    if auth.spf in ("fail", "softfail"):
        findings.append(Finding("HDR-SPF", "header", "medium" if auth.spf == "softfail" else "high",
                                f"SPF {auth.spf}",
                                f"Sending server not authorized to send for {email.from_domain}"))
    if auth.dkim in ("fail", "none", "neutral", "permerror"):
        findings.append(Finding("HDR-DKIM", "header", "medium", f"DKIM {auth.dkim}",
                                "Message is not covered by a valid DKIM signature"))
    if auth.dmarc == "fail":
        findings.append(Finding("HDR-DMARC", "header", "high", "DMARC fail",
                                f"Message failed DMARC alignment for From domain {email.from_domain}",
                                "T1656 Impersonation"))
    if auth.spf is None and auth.dkim is None and auth.dmarc is None:
        findings.append(Finding("HDR-NOAUTH", "header", "low", "No authentication results",
                                "No Authentication-Results/Received-SPF header present; sender unverified"))
    return findings


def check_sender_alignment(email: ParsedEmail) -> list[Finding]:
    findings = []
    ref = reference()
    from_reg = registrable_domain(email.from_domain) if email.from_domain else ""

    if email.reply_to_domain and registrable_domain(email.reply_to_domain) != from_reg:
        freemail = email.reply_to_domain in ref["freemail"]
        findings.append(Finding(
            "HDR-REPLYTO", "header", "high" if freemail else "medium",
            "Reply-To diverts responses to a different domain",
            f"From: {email.from_address} / Reply-To: {email.reply_to}"
            + (" (free webmail)" if freemail else ""),
            "T1656 Impersonation"))

    if email.return_path_domain and registrable_domain(email.return_path_domain) != from_reg:
        findings.append(Finding(
            "HDR-RETURNPATH", "header", "low", "Envelope sender differs from From domain",
            f"Return-Path: {email.return_path} / From: {email.from_address}"))

    if email.from_domain:
        lookalike = find_lookalike(email.from_domain, ref["brands"])
        if lookalike:
            findings.append(Finding(
                "HDR-LOOKALIKE", "header", "high", "Sender domain impersonates a known brand",
                f"{email.from_domain} impersonates {lookalike[0]} via {lookalike[1]}",
                "T1656 Impersonation"))
    return findings


def check_display_name(email: ParsedEmail) -> list[Finding]:
    findings = []
    name = email.from_name or ""
    if not name:
        return findings
    ref = reference()

    embedded = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", name)
    if embedded and registrable_domain(embedded.group(1)) != registrable_domain(email.from_domain):
        findings.append(Finding(
            "HDR-DISPLAY-ADDR", "header", "high",
            "Display name contains a different email address",
            f"'{name}' <{email.from_address}>", "T1656 Impersonation"))

    from_reg = registrable_domain(email.from_domain) if email.from_domain else ""
    lowered = name.lower()
    for brand, domains in ref["brands"].items():
        if re.search(rf"\b{re.escape(brand.lower())}\b", lowered) and from_reg not in domains:
            findings.append(Finding(
                "HDR-DISPLAY-BRAND", "header", "medium",
                f"Display name claims to be {brand} but sender domain is unrelated",
                f"'{name}' <{email.from_address}>", "T1656 Impersonation"))
            break
    return findings


# --------------------------------------------------------------------------- urls

def check_links(email: ParsedEmail) -> list[Finding]:
    ref = reference()
    findings = []
    seen: set[tuple[str, str]] = set()
    for link in email.links:
        if link.source == "form":
            findings.append(Finding(
                "URL-FORM", "url", "high", "HTML form embedded in email body",
                f"Form submits to {link.href}", "T1598.003 Spearphishing Link"))
        for ind in analyze_url(link.href, link.text, brands=ref["brands"],
                               shorteners=ref["shorteners"], suspicious_tlds=ref["suspicious_tlds"]):
            key = (ind.code, ind.detail)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(ind.code, "url", ind.severity, _URL_TITLES[ind.code],
                                    f"{ind.detail} -> {link.href}", "T1566.002 Spearphishing Link"))
    return findings


_URL_TITLES = {
    "URL-SCHEME": "Link uses a dangerous URL scheme",
    "URL-USERINFO": "Link hides real destination using userinfo (@)",
    "URL-IP": "Link points to a raw IP address",
    "URL-PUNYCODE": "Internationalized (punycode) domain in link",
    "URL-SHORTENER": "Link uses a URL shortener",
    "URL-TLD": "Link uses a frequently-abused TLD",
    "URL-DEEP-SUBDOMAIN": "Link has unusually deep subdomain nesting",
    "URL-LOOKALIKE": "Link domain impersonates a known brand",
    "URL-CRED-PATH": "Credential-harvesting path on lookalike domain",
    "URL-MISMATCH": "Link text and real destination differ",
}


# --------------------------------------------------------------------------- attachments

def _magic(payload: bytes) -> str | None:
    if payload.startswith(b"MZ"):
        return "pe"
    if payload.startswith(b"PK\x03\x04"):
        return "zip"
    if payload.startswith(b"%PDF"):
        return "pdf"
    if payload.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if payload[:512].lstrip().lower().startswith((b"<html", b"<!doctype html", b"<script")):
        return "html"
    return None


_EXPECTED_MAGIC = {
    "pdf": {"pdf"}, "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"}, "zip": {"zip"},
    "doc": {"ole"}, "xls": {"ole"}, "ppt": {"ole"}, "docm": {"zip"}, "xlsm": {"zip"},
    "txt": {None}, "csv": {None}, "jpg": {None}, "png": {None},
}


def _extensions(filename: str) -> list[str]:
    return [p.lower() for p in filename.split(".")[1:]]


def _check_one_attachment(att: Attachment) -> list[Finding]:
    ref = reference()
    findings = []
    exts = _extensions(att.filename)
    final = exts[-1] if exts else ""
    magic = _magic(att.payload)
    evidence = f"{att.filename} (sha256 {att.sha256[:16]}...)"

    if final in ref["dangerous_ext"]:
        findings.append(Finding("ATT-EXEC", "attachment", "critical",
                                f"Executable/script attachment (.{final})", evidence,
                                "T1566.001 Spearphishing Attachment"))
    if len(exts) >= 2 and final in ref["dangerous_ext"] | ref["archive_ext"] | {"html", "htm"} \
            and exts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}:
        findings.append(Finding("ATT-DOUBLE-EXT", "attachment", "high",
                                "Double file extension disguises real type", evidence,
                                "T1036.007 Double File Extension"))
    if magic == "pe" and final not in ref["dangerous_ext"]:
        findings.append(Finding("ATT-MAGIC", "attachment", "critical",
                                "Windows executable disguised with a benign extension",
                                f"{evidence} has MZ header but .{final} extension",
                                "T1036.008 Masquerade File Type"))
    elif final in _EXPECTED_MAGIC and magic not in _EXPECTED_MAGIC[final] and att.size > 0:
        findings.append(Finding("ATT-MAGIC", "attachment", "medium",
                                "File content does not match its extension",
                                f"{evidence}: .{final} but content looks like {magic or 'unknown'}",
                                "T1036.008 Masquerade File Type"))
    if final in ("html", "htm", "shtml", "svg") or magic == "html":
        findings.append(Finding("ATT-HTML", "attachment", "high",
                                "HTML/SVG attachment (credential harvesting / HTML smuggling)",
                                evidence, "T1027.006 HTML Smuggling"))

    has_vba = False
    if magic == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(att.payload)) as zf:
                names = zf.namelist()
                encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
        except zipfile.BadZipFile:
            names, encrypted = [], False
        has_vba = any(n.lower().endswith("vbaproject.bin") for n in names)
        inner_exec = [n for n in names if (_extensions(n) or [""])[-1] in ref["dangerous_ext"]]
        if inner_exec:
            findings.append(Finding("ATT-ARCHIVE-EXEC", "attachment", "critical",
                                    "Archive contains executable/script content",
                                    f"{evidence} contains {', '.join(inner_exec[:5])}",
                                    "T1566.001 Spearphishing Attachment"))
        if encrypted:
            findings.append(Finding("ATT-ENCRYPTED", "attachment", "high",
                                    "Password-protected archive (evades gateway scanning)",
                                    evidence, "T1027.013 Encrypted/Encoded File"))
    if has_vba or magic == "ole" and b"VBA" in att.payload:
        findings.append(Finding("ATT-MACRO", "attachment", "critical",
                                "Office document contains VBA macros", evidence,
                                "T1204.002 Malicious File"))
    elif final in ref["macro_ext"]:
        findings.append(Finding("ATT-MACRO", "attachment", "high",
                                "Macro-enabled Office format", evidence,
                                "T1204.002 Malicious File"))
    return findings


def check_attachments(email: ParsedEmail) -> list[Finding]:
    findings = []
    for att in email.attachments:
        findings.extend(_check_one_attachment(att))
    return findings


# --------------------------------------------------------------------------- content

_URGENCY = re.compile(
    r"\b(urgent(?:ly)?|immediately|within 24 hours|within 48 hours|account (?:will be )?(?:suspended|locked|closed|"
    r"disabled)|final notice|action required|unusual (?:sign-?in )?activity|verify your (?:account|identity)|"
    r"expire[sd]? (?:today|soon))\b", re.IGNORECASE)
_CREDENTIALS = re.compile(
    r"\b(confirm|verify|update|re-?enter|validate)\b.{0,40}\b(password|credentials|login details|"
    r"payment (?:details|information)|card details|ssn|social security)\b", re.IGNORECASE)
_BEC = re.compile(
    r"\b(gift ?cards?|wire transfer|bank (?:details|account) (?:has |have )?(?:changed|updated)|"
    r"new (?:bank|banking) details|are you (?:available|at your desk)|keep this (?:confidential|between us)|"
    r"process (?:a|the) payment|itunes cards?)\b", re.IGNORECASE)
_PROMPT_INJECTION = re.compile(
    r"\b(ignore (?:all |any )?(?:previous|prior|above) (?:instructions|prompts)|"
    r"you are (?:now )?an? (?:ai|assistant|language model)|system prompt|"
    r"(?:ai|llm|assistant)[, ]+(?:please )?(?:mark|classify|label) this (?:email|message) as (?:safe|legitimate)|"
    r"do not (?:flag|report) this (?:email|message))", re.IGNORECASE)
_ENABLE_CONTENT = re.compile(r"\benabl(?:e|ing) (?:editing|content|macros)\b", re.IGNORECASE)
_ARCHIVE_PASSWORD = re.compile(r"\b(password|passcode|pwd)\s*(?:is|:)\s*\S+", re.IGNORECASE)


def check_content(email: ParsedEmail) -> list[Finding]:
    findings = []
    text = " ".join(filter(None, [email.subject, email.visible_text]))
    all_text = f"{text} {email.hidden_text}"

    if m := _URGENCY.search(text):
        findings.append(Finding("CNT-URGENCY", "content", "low", "Urgency / pressure language",
                                f"…{m.group(0)}…"))
    if m := _CREDENTIALS.search(text):
        findings.append(Finding("CNT-CREDENTIALS", "content", "medium", "Requests credentials or payment data",
                                f"…{m.group(0)}…", "T1598 Phishing for Information"))
    if m := _BEC.search(text):
        freemail = email.from_domain in reference()["freemail"] or (
            email.reply_to_domain in reference()["freemail"])
        findings.append(Finding("CNT-BEC", "content", "high" if freemail else "medium",
                                "Business-email-compromise payment/gift-card lure",
                                f"…{m.group(0)}…" + (" (from/reply-to free webmail)" if freemail else ""),
                                "T1656 Impersonation"))
    if m := _PROMPT_INJECTION.search(all_text):
        findings.append(Finding("CNT-PROMPT-INJECTION", "content", "high",
                                "Embedded instructions targeting AI email assistants/triage",
                                f"…{m.group(0)}…" + (" (in CSS-hidden text)" if m.group(0) in email.hidden_text else ""),
                                "T1566 Phishing"))
    elif len(email.hidden_text) >= 40:
        findings.append(Finding("CNT-HIDDEN-TEXT", "content", "low",
                                "Significant CSS-hidden text (filter evasion / salting)",
                                f"{len(email.hidden_text)} chars hidden: {email.hidden_text[:60]}…"))
    if email.attachments and (m := _ENABLE_CONTENT.search(text)):
        findings.append(Finding("CNT-ENABLE-MACROS", "content", "medium",
                                "Instructs user to enable editing/macros",
                                f"…{m.group(0)}…", "T1204.002 Malicious File"))
    if email.attachments and (m := _ARCHIVE_PASSWORD.search(text)):
        findings.append(Finding("CNT-ATTACH-PASSWORD", "content", "medium",
                                "Body supplies a password for an attachment",
                                f"…{m.group(0)}…", "T1027.013 Encrypted/Encoded File"))
    return findings


ALL_CHECKS: list[Callable[[ParsedEmail], list[Finding]]] = [
    check_authentication,
    check_sender_alignment,
    check_display_name,
    check_links,
    check_attachments,
    check_content,
]


def run_checks(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(email))
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity), reverse=True)
    return findings
