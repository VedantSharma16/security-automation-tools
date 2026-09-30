"""Detection rules. Each analyzer takes a ParsedEmail and returns findings."""
from __future__ import annotations

import ipaddress
import re
from difflib import SequenceMatcher

from .models import Finding, ParsedEmail

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
DANGEROUS_EXT = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".bat", ".cmd", ".ps1",
    ".lnk", ".hta", ".iso", ".img", ".jar", ".msi", ".dll", ".chm",
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".xlam"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}
SUSPICIOUS_TLDS = {".zip", ".mov", ".xyz", ".top", ".click", ".work", ".gq", ".tk", ".ml", ".cf"}
BRANDS = ["microsoft", "office365", "paypal", "apple", "google", "amazon", "docusign", "dropbox", "netflix", "linkedin"]
URGENCY = [
    "urgent", "immediately", "within 24 hours", "account suspended", "verify your account",
    "password expires", "unusual sign-in", "action required", "final notice", "confirm your identity",
    "wire transfer", "gift card", "invoice attached",
]
_LEET = str.maketrans("01358", "oleas")


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[1] if "@" in addr else ""


def _registrable(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def check_auth(p: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    blob = f"{p.auth_results} {p.received_spf}".lower()
    if not blob.strip():
        return [Finding("auth.missing", "low", "No SPF/DKIM/DMARC results present in headers", mitre="T1566")]
    for mech, sev in (("spf", "medium"), ("dkim", "medium"), ("dmarc", "high")):
        m = re.search(rf"\b{mech}=(\w+)", blob) or (
            re.match(r"\s*(\w+)", p.received_spf.lower()) if mech == "spf" and p.received_spf else None
        )
        if m and m.group(1) in ("fail", "softfail", "permerror", "temperror"):
            out.append(Finding(f"auth.{mech}_fail", sev, f"{mech.upper()} check did not pass ({m.group(1)})",
                               evidence=m.group(0), mitre="T1566"))
    return out


def check_sender(p: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    fd, rd, rp = _domain(p.from_addr), _domain(p.reply_to), _domain(p.return_path)
    if rd and fd and _registrable(rd) != _registrable(fd):
        out.append(Finding("sender.reply_to_mismatch", "high",
                           "Reply-To domain differs from From domain (reply hijack)",
                           evidence=f"From={fd} Reply-To={rd}", mitre="T1566.002"))
    if rp and fd and _registrable(rp) != _registrable(fd):
        out.append(Finding("sender.return_path_mismatch", "medium",
                           "Return-Path domain differs from From domain",
                           evidence=f"From={fd} Return-Path={rp}", mitre="T1566"))
    disp = p.from_display.lower()
    dm = re.search(r"[\w.+-]+@([\w.-]+)", disp)
    if dm and fd and _registrable(dm.group(1)) != _registrable(fd):
        out.append(Finding("sender.display_name_spoof", "high",
                           "Display name contains a different email domain than the real sender",
                           evidence=p.from_display, mitre="T1656"))
    for b in BRANDS:
        if b in disp and b not in fd:
            out.append(Finding("sender.brand_impersonation", "medium",
                               f"Display name invokes '{b}' but sender domain is unrelated",
                               evidence=f"{p.from_display} <{p.from_addr}>", mitre="T1656"))
            break
    return out


def _lookalike(host: str) -> str | None:
    label = _registrable(host).split(".")[0]
    norm = label.translate(_LEET)
    for b in BRANDS:
        if label == b:
            return None
        if b in norm.replace("-", "") or SequenceMatcher(None, norm, b).ratio() >= 0.85:
            return b
    return None


def check_urls(p: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    for u in p.urls:
        h = u.host
        if not h:
            continue
        try:
            ipaddress.ip_address(h)
            out.append(Finding("url.ip_host", "high", "Link points at a raw IP address", u.href, "T1566.002"))
        except ValueError:
            pass
        if h in SHORTENERS:
            out.append(Finding("url.shortener", "medium", "Link uses a URL shortener hiding its destination", u.href, "T1566.002"))
        if "xn--" in h:
            out.append(Finding("url.punycode", "high", "Punycode (possible homograph) domain", u.href, "T1566.002"))
        if any(h.endswith(t) for t in SUSPICIOUS_TLDS):
            out.append(Finding("url.suspicious_tld", "low", "Link uses a TLD commonly abused for phishing", u.href, "T1566.002"))
        if u.href.lower().startswith("http://"):
            out.append(Finding("url.no_tls", "low", "Link is not HTTPS", u.href, "T1566.002"))
        if "@" in u.href.split("//", 1)[-1].split("/", 1)[0]:
            out.append(Finding("url.userinfo", "high", "URL embeds credentials-style userinfo to disguise the host", u.href, "T1566.002"))
        brand = _lookalike(h)
        if brand:
            out.append(Finding("url.lookalike_domain", "high", f"Domain resembles '{brand}' but is not it", u.href, "T1583.001"))
        # anchor text shows one domain, href goes elsewhere
        tm = re.search(r"(?:https?://)?([\w-]+(?:\.[\w-]+)+)", u.text.lower())
        if tm and _registrable(tm.group(1)) != _registrable(h):
            out.append(Finding("url.text_href_mismatch", "high",
                               "Visible link text shows a different domain than the real destination",
                               f"text={u.text!r} href={u.href}", "T1566.002"))
    return out


def check_attachments(p: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    for a in p.attachments:
        name = a.filename.lower()
        exts = ["." + e for e in name.split(".")[1:]]
        last = exts[-1] if exts else ""
        if last in DANGEROUS_EXT:
            sev = "critical" if len(exts) > 1 and exts[-2] in DOC_EXT else "high"
            desc = "Executable/script attachment" + (" with double extension masquerading as a document" if sev == "critical" else "")
            out.append(Finding("attachment.dangerous", sev, desc, a.filename, "T1204.002"))
        elif last in MACRO_EXT:
            out.append(Finding("attachment.macro", "high", "Macro-enabled Office attachment", a.filename, "T1204.002"))
        elif last in ARCHIVE_EXT:
            out.append(Finding("attachment.archive", "medium", "Archive attachment can hide payloads from scanning", a.filename, "T1027"))
    return out


def check_lures(p: ParsedEmail) -> list[Finding]:
    text = f"{p.subject}\n{p.body_text}".lower()
    hits = [k for k in URGENCY if k in text]
    if len(hits) >= 2:
        return [Finding("content.social_engineering", "medium", "Multiple urgency/pressure phrases",
                        ", ".join(hits), "T1566")]
    if hits:
        return [Finding("content.social_engineering", "low", "Urgency/pressure phrase", hits[0], "T1566")]
    return []


ALL_CHECKS = (check_auth, check_sender, check_urls, check_attachments, check_lures)
