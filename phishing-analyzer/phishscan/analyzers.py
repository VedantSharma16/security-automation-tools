"""Independent, deterministic analyzers. Each takes a ParsedEmail -> list[Finding]."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from .models import Finding
from .parser import ParsedEmail, addr_domain

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "work", "support"}
BRANDS = ["paypal", "microsoft", "office365", "apple", "amazon", "google", "netflix", "docusign", "dhl", "fedex", "bank"]
URGENCY = ["urgent", "immediately", "within 24 hours", "account suspended", "verify your account",
           "unusual activity", "password expires", "final notice", "act now", "locked"]
CREDENTIAL_WORDS = ["password", "login", "sign in", "verify", "confirm your identity", "ssn", "credentials"]
DANGEROUS_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "hta", "lnk", "iso", "img",
                 "jar", "msi", "wsf", "dll"}
MACRO_EXT = {"docm", "xlsm", "pptm", "xlam", "dotm"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar"}


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _registered(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_headers(e: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    auth = e.auth_results.lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", auth)
        if not m:
            out.append(Finding(f"{mech}_missing", "LOW", f"No {mech.upper()} result in Authentication-Results"))
        elif m.group(1) != "pass":
            sev = "HIGH" if mech in ("dmarc", "spf") else "MEDIUM"
            out.append(Finding(f"{mech}_fail", sev, f"{mech.upper()} did not pass", f"{mech}={m.group(1)}", "T1566"))
    from_dom = addr_domain(e.from_addr)
    for label, addr in (("reply_to", e.reply_to), ("return_path", e.return_path)):
        dom = addr_domain(addr)
        if dom and from_dom and _registered(dom) != _registered(from_dom):
            out.append(Finding(f"{label}_mismatch", "MEDIUM" if label == "return_path" else "HIGH",
                               f"{label.replace('_', '-').title()} domain differs from From domain",
                               f"From={from_dom} {label}={dom}", "T1566.001"))
    display = e.from_name.lower()
    for brand in BRANDS:
        if brand in display and brand not in from_dom:
            out.append(Finding("display_name_spoof", "HIGH", f"Display name impersonates '{brand}' but sender domain is unrelated",
                               f"{e.from_name} <{e.from_addr}>", "T1656"))
            break
    return out


def analyze_urls(e: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    for link in e.links:
        host = _host(link.href)
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
            out.append(Finding("ip_url", "HIGH", "Link points at a raw IP address", link.href, "T1566.002"))
        except ValueError:
            pass
        if host in SHORTENERS:
            out.append(Finding("url_shortener", "MEDIUM", "Link uses a URL shortener hiding its destination", link.href, "T1566.002"))
        if host.startswith("xn--") or ".xn--" in host:
            out.append(Finding("punycode_domain", "HIGH", "Link uses a punycode (possible homograph) domain", link.href, "T1566.002"))
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            out.append(Finding("suspicious_tld", "LOW", "Link uses a TLD frequently abused for phishing", link.href))
        if "@" in link.href.split("//", 1)[-1].split("/", 1)[0]:
            out.append(Finding("userinfo_url", "HIGH", "URL contains user-info '@' trick to disguise host", link.href, "T1566.002"))
        for brand in BRANDS:
            if brand in host and not (host == f"{brand}.com" or host.endswith(f".{brand}.com")):
                out.append(Finding("brand_lookalike", "HIGH", f"Host embeds brand '{brand}' on an unrelated domain", link.href, "T1583.001"))
                break
        shown = re.search(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", link.text.lower())
        if shown and _registered(shown.group(1)) != _registered(host):
            out.append(Finding("link_text_mismatch", "CRITICAL", "Visible link text shows a different domain than the real target",
                               f"text={shown.group(1)} href={host}", "T1566.002"))
    return out


def analyze_attachments(e: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    for a in e.attachments:
        parts = a.filename.lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if len(parts) > 2 and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"} and ext in DANGEROUS_EXT:
            out.append(Finding("double_extension", "CRITICAL", "Attachment masquerades with a double extension", a.filename, "T1036.007"))
        elif ext in DANGEROUS_EXT:
            out.append(Finding("dangerous_attachment", "HIGH", "Executable/script attachment type", a.filename, "T1566.001"))
        elif ext in MACRO_EXT:
            out.append(Finding("macro_attachment", "HIGH", "Macro-enabled Office document", a.filename, "T1204.002"))
        elif ext in ARCHIVE_EXT:
            out.append(Finding("archive_attachment", "LOW", "Archive may conceal payload from scanners", a.filename, "T1027"))
    return out


def analyze_content(e: ParsedEmail) -> list[Finding]:
    body = f"{e.subject}\n{e.text}".lower()
    out: list[Finding] = []
    hits = [w for w in URGENCY if w in body]
    if hits:
        out.append(Finding("urgency_language", "MEDIUM" if len(hits) > 1 else "LOW",
                           "Pressure/urgency language typical of social engineering", ", ".join(hits), "T1566"))
    creds = [w for w in CREDENTIAL_WORDS if w in body]
    if creds and e.links:
        out.append(Finding("credential_lure", "MEDIUM", "Credential-themed wording alongside links", ", ".join(creds), "T1566.002"))
    return out


ANALYZERS = [analyze_headers, analyze_urls, analyze_attachments, analyze_content]
