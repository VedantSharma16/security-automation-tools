"""Rule-based phishing detectors. Each returns a list of Findings."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlparse

from .models import Finding, ParsedEmail

BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "office365": "microsoft.com",
    "google": "google.com", "apple": "apple.com", "amazon": "amazon.com",
    "docusign": "docusign.com", "dhl": "dhl.com", "netflix": "netflix.com",
    "linkedin": "linkedin.com", "dropbox": "dropbox.com", "okta": "okta.com",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "work", "support"}
EXEC_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "lnk", "jar", "msi", "hta", "iso", "img", "com", "pif"}
MACRO_EXT = {"docm", "xlsm", "pptm", "xlm", "dotm"}
LURE_EXT = {"html", "htm", "svg", "xhtml"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "ppt", "pptx"}
URGENCY = [
    "urgent", "immediately", "within 24 hours", "account suspended", "will be suspended", "verify your account",
    "confirm your identity", "password expires", "unusual sign-in", "action required", "final notice",
    "limited time", "wire transfer", "gift card", "payment overdue",
]
CRED_LURE = ["password", "log in", "login", "sign in", "credentials", "verify", "one-time code", "mfa"]


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def registrable(host: str) -> str:
    """Crude eTLD+1 (last two labels; three for common 2-level ccTLDs)."""
    labels = [l for l in host.lower().strip(".").split(".") if l]
    if len(labels) >= 3 and labels[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _skeleton(s: str) -> str:
    """Fold common homoglyphs/digit swaps so 'paypa1' ~ 'paypal'."""
    s = unicodedata.normalize("NFKD", s.lower())
    table = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "|": "l"})
    s = s.translate(table).replace("rn", "m").replace("vv", "w")
    return "".join(c for c in s if c.isalnum())


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(domain: str) -> str | None:
    """Return the legitimate domain this one imitates, or None."""
    reg = registrable(domain)
    if not reg or reg in BRANDS.values():
        return None
    sld = reg.split(".")[0]
    if "xn--" in domain:
        for brand, legit in BRANDS.items():
            if brand in _skeleton(domain.replace("xn--", "")):
                return legit
    for brand, legit in BRANDS.items():
        sk = _skeleton(sld)
        if sk == brand and sld != brand:
            return legit
        if len(brand) >= 5 and _edit_distance(sk, brand) == 1:
            return legit
        if brand in sk and sld != brand:  # paypal-secure, microsoft-login
            return legit
    return None


def detect_sender(p: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    fd = domain_of(p.from_addr)
    if p.reply_to and registrable(domain_of(p.reply_to)) != registrable(fd):
        out.append(Finding("reply_to_mismatch", "high", "Reply-To domain differs from From",
                           f"Replies go to {p.reply_to}, not {p.from_addr}.", "T1566",
                           [p.from_addr, p.reply_to]))
    if p.return_path and fd and registrable(domain_of(p.return_path)) != registrable(fd):
        out.append(Finding("return_path_mismatch", "medium", "Return-Path domain differs from From",
                           f"Envelope sender {p.return_path} does not align with {p.from_addr}.", "T1566",
                           [p.from_addr, p.return_path]))
    name = p.from_name.lower()
    for brand, legit in BRANDS.items():
        if brand in name and registrable(fd) != legit:
            out.append(Finding("display_name_spoof", "high", f"Display name impersonates {brand}",
                               f'"{p.from_name}" is sent from {fd}, not {legit}.', "T1656", [p.from_name, p.from_addr]))
            break
    look = lookalike_of(fd) if fd else None
    if look:
        out.append(Finding("lookalike_sender_domain", "high", "Sender domain imitates a known brand",
                           f"{fd} resembles {look}.", "T1583.001", [fd, look]))
    return out


def detect_auth(p: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    bad = {m: v for m, v in p.auth.items() if v in {"fail", "softfail", "permerror", "temperror"}}
    for mech, verdict in bad.items():
        sev = "high" if mech == "dmarc" or verdict == "fail" else "medium"
        out.append(Finding(f"{mech}_{verdict}", sev, f"{mech.upper()} {verdict}",
                           f"Authentication-Results reports {mech}={verdict}.", "T1566", [f"{mech}={verdict}"]))
    if not p.auth:
        out.append(Finding("no_auth_results", "low", "No Authentication-Results header",
                           "Cannot confirm SPF/DKIM/DMARC; treat sender identity as unverified."))
    return out


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def detect_urls(p: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    for link in p.links:
        host = _host(link.href)
        if not host:
            continue
        is_ip = True
        try:
            ipaddress.ip_address(host)
            out.append(Finding("ip_url", "high", "URL uses a raw IP address", link.href, "T1566.002", [link.href]))
        except ValueError:
            is_ip = False
        if host in SHORTENERS:
            out.append(Finding("url_shortener", "medium", "Shortened URL hides destination", link.href, "T1566.002", [link.href]))
        if "xn--" in host:
            out.append(Finding("punycode_url", "high", "Punycode (IDN) hostname", f"{host} may be a homograph attack.", "T1566.002", [link.href]))
        if "@" in urlparse(link.href).netloc:
            out.append(Finding("userinfo_url", "high", "URL contains user-info '@' trick", link.href, "T1566.002", [link.href]))
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            out.append(Finding("risky_tld", "low", "URL on high-abuse TLD", host, "T1566.002", [link.href]))
        look = None if is_ip else lookalike_of(host)
        if look:
            out.append(Finding("lookalike_url", "high", "URL domain imitates a known brand", f"{host} resembles {look}.", "T1566.002", [link.href]))
        shown = re.search(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", link.text.lower())
        if shown and registrable(shown.group(1)) != registrable(host):
            out.append(Finding("link_text_mismatch", "high", "Link text does not match destination",
                               f'Displays "{link.text}" but points to {host}.', "T1566.002", [link.text, link.href]))
    return out


def detect_attachments(p: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    for a in p.attachments:
        parts = a.filename.lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if len(parts) > 2 and parts[-2] in DOC_EXT and ext in EXEC_EXT:
            out.append(Finding("double_extension", "critical", "Double-extension attachment",
                               f"{a.filename} masquerades as a document.", "T1036.007", [a.filename, a.sha256]))
        elif ext in EXEC_EXT:
            out.append(Finding("executable_attachment", "critical", "Executable/script attachment",
                               f"{a.filename} ({ext}).", "T1204.002", [a.filename, a.sha256]))
        elif ext in MACRO_EXT:
            out.append(Finding("macro_attachment", "high", "Macro-enabled Office attachment", a.filename, "T1204.002", [a.filename, a.sha256]))
        elif ext in LURE_EXT:
            out.append(Finding("html_attachment", "high", "HTML/SVG attachment (credential-harvest smuggling)", a.filename, "T1566.001", [a.filename, a.sha256]))
        elif ext in {"zip", "rar", "7z", "gz"}:
            out.append(Finding("archive_attachment", "low", "Archive attachment", f"{a.filename}: contents not inspected.", "T1027", [a.filename, a.sha256]))
    return out


def detect_content(p: ParsedEmail) -> list[Finding]:
    blob = f"{p.subject}\n{p.text}".lower()
    hits = [k for k in URGENCY if k in blob]
    out: list[Finding] = []
    if len(hits) >= 2:
        out.append(Finding("urgency_language", "medium", "Pressure / urgency language", ", ".join(hits), "T1566", hits))
    if hits and p.links and any(k in blob for k in CRED_LURE):
        out.append(Finding("credential_lure", "medium", "Urgency combined with credential prompt and link",
                           "Typical credential-harvesting pattern.", "T1598.003", hits[:3]))
    return out


def detect_all(p: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    for fn in (detect_sender, detect_auth, detect_urls, detect_attachments, detect_content):
        out.extend(fn(p))
    return out
