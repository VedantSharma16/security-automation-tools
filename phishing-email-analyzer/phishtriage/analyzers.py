"""Independent, deterministic analyzers. Each takes a ParsedEmail and returns Indicators.

Every indicator carries the concrete evidence that triggered it, so an analyst
can verify the call in seconds — nothing here is a black box.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import heuristics
from .domains import (
    brand_for_domain,
    find_lookalike,
    is_ip,
    load_brands,
    registrable_domain,
    to_unicode,
)
from .indicators import Indicator
from .parser import ParsedEmail

_RLO = "‮"

# Magic-byte signatures -> extensions that legitimately carry them.
_MAGIC = [
    (b"MZ", "PE executable", {"exe", "dll", "scr", "com", "cpl", "sys", "msi"}),
    (b"%PDF", "PDF document", {"pdf"}),
    (b"PK\x03\x04", "ZIP container", {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm",
                                       "jar", "apk", "odt", "ods", "odp", "epub", "appx", "msix", "xlam"}),
    (b"\xd0\xcf\x11\xe0", "OLE2 compound file", {"doc", "xls", "ppt", "msi", "msg", "dot", "xlt"}),
    (b"Rar!", "RAR archive", {"rar"}),
    (b"7z\xbc\xaf", "7-Zip archive", {"7z"}),
    (b"{\\rtf", "RTF document", {"rtf", "doc"}),
]

_SMUGGLING_MARKERS = ("atob(", "new blob", "createobjecturl", "mssaveoropenblob", "download=",
                      "fromcharcode", "unescape(", "eval(")
_CREDENTIAL_FORM_MARKERS = ('type="password"', "type='password'", "type=password", "<form")


def _phrases_found(text: str, phrases: list[str]) -> list[str]:
    lowered = " ".join(text.lower().split())
    return [p for p in phrases if p in lowered]


# --------------------------------------------------------------------------- auth

def analyze_authentication(email: ParsedEmail) -> list[Indicator]:
    auth = email.auth
    if not auth.raw:
        return [Indicator("auth_results_missing", "authentication", "info",
                          "No Authentication-Results header",
                          "SPF/DKIM/DMARC verdicts are unavailable, so sender authenticity "
                          "cannot be confirmed from this copy of the message.")]

    out: list[Indicator] = []
    spec = {
        "spf": {"fail": "high", "softfail": "medium", "permerror": "medium", "none": "low"},
        "dkim": {"fail": "medium", "permerror": "medium", "none": "low"},
        "dmarc": {"fail": "high", "none": "low"},
    }
    for method, levels in spec.items():
        verdict = getattr(auth, method)
        if verdict in levels:
            out.append(Indicator(
                f"{method}_{verdict}", "authentication", levels[verdict],
                f"{method.upper()} {verdict}",
                f"The receiving server recorded {method.upper()}={verdict} for this message.",
                evidence=f"{method}={verdict}",
                mitre=["T1656"] if verdict == "fail" else [],
            ))
    if not out and all(getattr(auth, m) == "pass" for m in ("spf", "dkim", "dmarc")):
        out.append(Indicator("auth_all_pass", "authentication", "info",
                             "SPF, DKIM and DMARC all pass",
                             "The sending domain is authenticated. Note this proves the mail came "
                             "from the From domain — not that the domain itself is trustworthy."))
    return out


# --------------------------------------------------------------------------- sender

def analyze_sender(email: ParsedEmail) -> list[Indicator]:
    out: list[Indicator] = []
    h = heuristics.load()
    sender = email.from_
    from_domain = sender.domain
    from_reg = registrable_domain(from_domain)

    if from_domain:
        match = find_lookalike(from_domain)
        if match:
            out.append(Indicator(
                "sender_lookalike_domain", "sender", "critical",
                f"Sender domain imitates {match.brand} ({match.technique})",
                match.detail, evidence=sender.address, mitre=["T1656", "T1583.001"],
            ))

    display = sender.display_name.lower()
    if display and from_domain and not brand_for_domain(from_domain):
        for brand, info in load_brands().items():
            if any(re.search(rf"\b{re.escape(k)}\b", display) for k in info["keywords"]):
                out.append(Indicator(
                    "display_name_brand_spoof", "sender", "high",
                    f"Display name claims to be {brand}",
                    f"Display name '{sender.display_name}' references {brand}, but the "
                    f"message was sent from '{from_domain}', which {brand} does not own.",
                    evidence=f'"{sender.display_name}" <{sender.address}>', mitre=["T1656"],
                ))
                break

    embedded = re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", sender.display_name)
    if any(e.lower() != sender.address for e in embedded):
        out.append(Indicator(
            "display_name_embedded_address", "sender", "high",
            "Display name contains a different email address",
            "A classic trick to make the visible sender look legitimate in clients that "
            "hide the real address.",
            evidence=f'"{sender.display_name}" <{sender.address}>', mitre=["T1656"],
        ))

    for rt in email.reply_to:
        if rt.domain and registrable_domain(rt.domain) != from_reg:
            freemail = rt.domain in h["freemail_domains"]
            out.append(Indicator(
                "reply_to_mismatch", "sender", "high" if freemail else "medium",
                "Reply-To diverts responses to a different domain",
                f"Replies go to '{rt.address}' instead of the sender domain '{from_domain}'"
                + (" (a free webmail provider)" if freemail else "") + ".",
                evidence=f"From: {sender.address} | Reply-To: {rt.address}", mitre=["T1656"],
            ))

    if email.return_path and "@" in email.return_path:
        rp_domain = email.return_path.rsplit("@", 1)[1]
        if registrable_domain(rp_domain) != from_reg:
            out.append(Indicator(
                "return_path_mismatch", "sender", "low",
                "Envelope sender differs from header From",
                f"Return-Path domain '{rp_domain}' does not match From domain '{from_domain}'. "
                "Common with bulk-mail providers; significant when combined with auth failures.",
                evidence=f"Return-Path: {email.return_path}",
            ))
    return out


# --------------------------------------------------------------------------- urls

def _domain_in_text(text: str) -> str | None:
    m = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:\s]|$)", text.strip().lower())
    return m.group(1) if m else None


def analyze_urls(email: ParsedEmail) -> list[Indicator]:
    h = heuristics.load()
    out: list[Indicator] = []
    seen: set[tuple[str, str]] = set()

    def add(ind: Indicator, key: str) -> None:
        if (ind.id, key) not in seen:
            seen.add((ind.id, key))
            out.append(ind)

    for link in email.links:
        url = link.url
        lowered = url.lower()
        if lowered.startswith(("mailto:", "tel:", "#", "cid:")) or not lowered:
            continue
        if lowered.startswith(("javascript:", "data:")):
            add(Indicator("url_script_scheme", "url", "high", "Link uses a script/data URI",
                          "javascript:/data: links execute or render attacker content directly "
                          "in the client or browser.", evidence=url[:120],
                          mitre=["T1566.002", "T1027.006"]), url[:40])
            continue

        if link.anchor_text == "<form action>":
            add(Indicator("html_form_post", "url", "high", "Message embeds an HTML form",
                          "Forms inside an email body submit typed data (often credentials) "
                          "directly to the attacker.", evidence=url, mitre=["T1598.003"]), url)

        parts = urlsplit(url if "://" in url else "http://" + url)
        host = (parts.hostname or "").lower()
        if not host:
            continue
        reg = registrable_domain(host)

        if "@" in parts.netloc:
            add(Indicator("url_userinfo_obfuscation", "url", "high",
                          "URL hides its real host behind an '@'",
                          f"Everything before '@' is ignored by the browser; the real host is '{host}'.",
                          evidence=url, mitre=["T1566.002"]), host)
        if is_ip(host):
            add(Indicator("url_ip_host", "url", "high", "Link points to a raw IP address",
                          "Legitimate services almost never link to bare IPs.",
                          evidence=url, mitre=["T1566.002"]), host)
            continue
        if "xn--" in host:
            add(Indicator("url_punycode", "url", "medium", "Internationalised (punycode) domain",
                          f"'{host}' displays as '{to_unicode(host)}'.", evidence=url,
                          mitre=["T1583.001"]), host)
        match = find_lookalike(host)
        if match:
            add(Indicator("url_lookalike_domain", "url", "critical",
                          f"Link domain imitates {match.brand} ({match.technique})",
                          match.detail, evidence=url, mitre=["T1566.002", "T1583.001"]), host)
        if reg in h["url_shorteners"]:
            add(Indicator("url_shortener", "url", "low", "URL shortener hides the destination",
                          f"'{host}' redirects to an unknown final URL.", evidence=url), host)
        if host.rsplit(".", 1)[-1] in h["suspicious_tlds"]:
            add(Indicator("url_suspicious_tld", "url", "medium", "High-abuse top-level domain",
                          f"'.{host.rsplit('.', 1)[-1]}' is disproportionately used for phishing.",
                          evidence=url), host)
        if any(host == d or host.endswith("." + d) for d in h["free_hosting_domains"]):
            add(Indicator("url_free_hosting", "url", "medium", "Link hosted on a free/dev platform",
                          f"'{host}' is on free hosting commonly abused for credential-harvest pages.",
                          evidence=url, mitre=["T1566.002"]), host)

        if link.source == "html" and link.anchor_text and link.anchor_text != "<form action>":
            shown = _domain_in_text(link.anchor_text)
            if shown and registrable_domain(shown) != reg:
                add(Indicator("url_text_mismatch", "url", "high",
                              "Visible link text points somewhere else",
                              f"Text shows '{shown}' but the link opens '{host}'.",
                              evidence=f"[{link.anchor_text}] -> {url}", mitre=["T1566.002"]), host)
    return out


# --------------------------------------------------------------------------- attachments

def _extensions(filename: str) -> list[str]:
    name = filename.lower().replace(_RLO, "").strip()
    parts = name.split(".")
    return parts[1:] if len(parts) > 1 else []


def analyze_attachments(email: ParsedEmail) -> list[Indicator]:
    h = heuristics.load()
    out: list[Indicator] = []
    body = email.body_text.lower()
    exe = set(h["executable_extensions"])
    decoy = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "rtf", "csv"}

    for att in email.attachments:
        name = att.filename
        exts = _extensions(name)
        final = exts[-1] if exts else ""
        ev = f"{name} (sha256 {att.sha256[:16]}…, {att.size} bytes)"

        if _RLO in name:
            out.append(Indicator("attachment_rlo", "attachment", "critical",
                                 "Filename uses a Right-to-Left Override character",
                                 "U+202E reverses how the filename renders to disguise its real extension.",
                                 evidence=ev, mitre=["T1036.002", "T1566.001"]))
        if len(exts) >= 2 and exts[-2] in decoy and final in exe:
            out.append(Indicator("attachment_double_extension", "attachment", "critical",
                                 "Executable disguised with a double extension",
                                 f"'{name}' looks like a .{exts[-2]} but is a .{final}.",
                                 evidence=ev, mitre=["T1036.007", "T1566.001", "T1204.002"]))
        elif final in exe:
            out.append(Indicator("attachment_executable", "attachment", "high",
                                 f"Executable or script attachment (.{final})",
                                 "Directly executable content is rarely sent legitimately by email.",
                                 evidence=ev, mitre=["T1566.001", "T1204.002"]))
        if final in h["macro_extensions"]:
            legacy = final in ("doc", "xls")
            out.append(Indicator("attachment_macro_capable", "attachment",
                                 "medium" if legacy else "high",
                                 f"Macro-capable Office document (.{final})",
                                 "Office macros remain a common initial-access payload.",
                                 evidence=ev, mitre=["T1566.001", "T1204.002"]))
        if final in h["archive_extensions"]:
            protected = "password" in body
            out.append(Indicator("attachment_archive", "attachment", "medium" if protected else "low",
                                 "Archive attachment" + (" with password in body" if protected else ""),
                                 "Password-protected archives are used to blind mail-gateway scanning."
                                 if protected else "Archives can conceal executable payloads from filters.",
                                 evidence=ev, mitre=["T1566.001"]))
        if final in h["html_extensions"]:
            sample = att.text_sample.lower()
            smuggling = [m for m in _SMUGGLING_MARKERS if m in sample]
            cred_form = any(m in sample for m in _CREDENTIAL_FORM_MARKERS)
            if len(smuggling) >= 2:
                out.append(Indicator("attachment_html_smuggling", "attachment", "critical",
                                     "HTML attachment shows HTML-smuggling behaviour",
                                     "Script assembles and drops a payload client-side, bypassing "
                                     "gateway file inspection.",
                                     evidence=f"{ev}; markers: {', '.join(smuggling)}",
                                     mitre=["T1027.006", "T1566.001"]))
            elif cred_form:
                out.append(Indicator("attachment_credential_form", "attachment", "high",
                                     "HTML attachment contains a login form",
                                     "Locally-rendered credential-harvest page; no URL for a proxy to block.",
                                     evidence=ev, mitre=["T1598.003"]))
            else:
                out.append(Indicator("attachment_html", "attachment", "medium",
                                     f"HTML/SVG attachment (.{final})",
                                     "Active-content attachments can render phishing pages or run script.",
                                     evidence=ev, mitre=["T1566.001"]))
        for magic, label, allowed in _MAGIC:
            if att.head.startswith(magic) and final not in allowed:
                out.append(Indicator("attachment_magic_mismatch", "attachment",
                                     "critical" if magic == b"MZ" else "medium",
                                     f"File content is a {label}, not .{final or '(none)'}",
                                     "The extension does not match the file's magic bytes.",
                                     evidence=ev, mitre=["T1036.007", "T1566.001"]))
                break
    return out


# --------------------------------------------------------------------------- content

def analyze_content(email: ParsedEmail) -> list[Indicator]:
    h = heuristics.load()
    text = f"{email.subject}\n{email.body_text}"
    out: list[Indicator] = []

    urgency = _phrases_found(text, h["urgency_phrases"])
    if urgency:
        out.append(Indicator("content_urgency", "content", "medium" if len(urgency) >= 3 else "low",
                             "Urgency / pressure language",
                             "Social-engineering pressure to act before thinking.",
                             evidence=", ".join(urgency)))
    creds = _phrases_found(text, h["credential_phrases"])
    if creds and email.links:
        out.append(Indicator("content_credential_request", "content", "medium",
                             "Asks the reader to sign in or verify credentials via a link",
                             "Credential lure paired with a clickable link.",
                             evidence=", ".join(creds), mitre=["T1598.003"]))
    bec = _phrases_found(text, h["bec_phrases"])
    if bec:
        out.append(Indicator("content_bec_language", "content", "medium" if len(bec) >= 2 else "low",
                             "Payment / BEC-style language",
                             "Language typical of business-email-compromise payment fraud.",
                             evidence=", ".join(bec)))
    return out


ANALYZERS = (analyze_authentication, analyze_sender, analyze_urls, analyze_attachments, analyze_content)


def run_all(email: ParsedEmail) -> list[Indicator]:
    indicators: list[Indicator] = []
    for analyzer in ANALYZERS:
        indicators.extend(analyzer(email))
    return indicators
