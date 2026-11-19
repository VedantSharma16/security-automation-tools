"""Independent, explainable phishing checks.

Each check takes a ParsedEmail (plus config) and returns zero or more Findings.
A Finding carries a severity, a score contribution, human-readable evidence,
and a MITRE ATT&CK technique so the output can feed straight into an IR ticket.
No check makes network calls; everything is derived from the message itself.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from ipaddress import ip_address
from urllib.parse import urlsplit

from .domains import (
    brands,
    decode_idna,
    find_lookalike,
    is_legitimate,
    load_intel,
    registrable_domain,
)
from .parser import Link, ParsedEmail, domain_of

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

T_SPEAR_LINK = "T1566.002"  # Phishing: Spearphishing Link
T_SPEAR_ATTACH = "T1566.001"  # Phishing: Spearphishing Attachment
T_PHISHING = "T1566"  # Phishing
T_IMPERSONATION = "T1656"  # Impersonation
T_CRED_HARVEST = "T1598.003"  # Phishing for Information: Spearphishing Link

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "hta", "ps1", "msi", "dll", "lnk", "jar", "cpl", "reg", "url", "scf", "chm",
}
CONTAINER_EXTENSIONS = {"iso", "img", "vhd", "vhdx", "zip", "rar", "7z", "cab", "ace"}
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "xls", "doc"}
SMUGGLING_EXTENSIONS = {"html", "htm", "shtml", "svg", "xhtml"}
DOCUMENT_MAGIC = {
    "pdf": b"%PDF",
    "docx": b"PK\x03\x04", "xlsx": b"PK\x03\x04", "pptx": b"PK\x03\x04", "zip": b"PK\x03\x04",
    "png": b"\x89PNG", "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff", "gif": b"GIF8",
}

URGENCY_PATTERNS = [
    r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bwithin (24|48) hours\b", r"\bact now\b",
    r"\bfinal (notice|warning)\b", r"\bsuspend(ed)?\b", r"\bwill be (closed|deactivated|deleted)\b",
    r"\bexpire[sd]?\b", r"\bunusual (sign-in|activity)\b", r"\blocked\b",
]
CREDENTIAL_PATTERNS = [
    r"\bverify your (account|identity|password)\b", r"\bconfirm your (account|details|password)\b",
    r"\b(re-?)?enter your password\b", r"\blog ?in to (restore|verify|unlock)\b",
    r"\bupdate your (payment|billing) (details|information)\b", r"\bsign in to review\b",
]
BEC_PATTERNS = [
    r"\bwire transfer\b", r"\bgift cards?\b", r"\bbank (details|account) (have|has) changed\b",
    r"\bupdated? (bank|banking|payment) (details|information)\b", r"\boutstanding invoice\b",
    r"\bare you available\b", r"\bkeep this confidential\b", r"\bpayment (today|urgently)\b",
]


@dataclass
class Finding:
    check: str
    title: str
    severity: str
    score: int
    evidence: list[str] = field(default_factory=list)
    mitre: str = T_PHISHING

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalysisConfig:
    protected_domains: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- headers


def check_authentication(email: ParsedEmail, cfg: AnalysisConfig) -> list[Finding]:
    auth = email.auth
    if auth.spf is None and auth.dkim is None and auth.dmarc is None:
        return [Finding(
            "auth_missing", "No Authentication-Results header", "low", 5,
            ["SPF/DKIM/DMARC verdicts unavailable; sender authenticity cannot be confirmed"],
        )]

    findings: list[Finding] = []
    if auth.dmarc in {"fail", "permerror"}:
        findings.append(Finding(
            "dmarc_fail", "DMARC failed", "high", 30,
            [f"dmarc={auth.dmarc} for From domain '{email.from_domain}'"], T_IMPERSONATION,
        ))
    failed = [f"{m}={v}" for m, v in (("spf", auth.spf), ("dkim", auth.dkim))
              if v in {"fail", "softfail", "permerror", "none"}]
    if failed:
        both = auth.spf in {"fail", "softfail"} and auth.dkim in {"fail", "none"}
        findings.append(Finding(
            "spf_dkim_fail", "SPF/DKIM did not pass", "medium" if both else "low",
            15 if both else 8, failed,
        ))
    return findings


def check_sender_mismatch(email: ParsedEmail, cfg: AnalysisConfig) -> list[Finding]:
    findings: list[Finding] = []
    from_dom = email.from_domain
    from_reg = registrable_domain(from_dom) if from_dom else ""

    foreign_reply = [r for r in email.reply_to
                     if registrable_domain(domain_of(r)) not in {from_reg, ""}]
    if foreign_reply:
        free = set(load_intel()["free_mail_domains"])
        to_free = any(domain_of(r) in free for r in foreign_reply)
        findings.append(Finding(
            "reply_to_mismatch", "Reply-To diverts responses to a different domain",
            "high" if to_free else "medium", 20 if to_free else 15,
            [f"From: {email.from_address}", *(f"Reply-To: {r}" for r in foreign_reply)]
            + (["Reply-To is a free webmail address (common in BEC)"] if to_free else []),
            T_IMPERSONATION,
        ))

    rp_dom = domain_of(email.return_path)
    if rp_dom and from_reg and registrable_domain(rp_dom) != from_reg:
        findings.append(Finding(
            "return_path_mismatch", "Envelope sender differs from header From", "low", 5,
            [f"Return-Path domain '{rp_dom}' vs From domain '{from_dom}'"],
        ))
    return findings


_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+\.)+[\w-]+")


def check_display_name(email: ParsedEmail, cfg: AnalysisConfig) -> list[Finding]:
    name = email.from_display.lower()
    if not name:
        return []
    findings: list[Finding] = []

    m = _EMAIL_IN_TEXT.search(name)
    if m and domain_of(m.group(0)) != email.from_domain:
        findings.append(Finding(
            "display_name_address_spoof", "Display name contains a different email address",
            "high", 25, [f"Display name '{email.from_display}' but sent from <{email.from_address}>"],
            T_IMPERSONATION,
        ))

    for brand in brands():
        if any(re.search(rf"\b{re.escape(k)}\b", name) for k in brand.keywords):
            if registrable_domain(email.from_domain) not in brand.domains:
                findings.append(Finding(
                    "display_name_brand_spoof",
                    f"Display name claims to be {brand.name} from an unrelated domain",
                    "high", 25,
                    [f"Display name '{email.from_display}' sent from '{email.from_domain}'"],
                    T_IMPERSONATION,
                ))
            break
    return findings


def check_sender_lookalike(email: ParsedEmail, cfg: AnalysisConfig) -> list[Finding]:
    hit = find_lookalike(email.from_domain, cfg.protected_domains)
    if not hit:
        return []
    return [Finding(
        "sender_lookalike_domain", f"Sender domain imitates {hit.brand}", "critical", 40,
        [f"{hit.technique}: {hit.detail}", f"From: {email.from_address}"], T_IMPERSONATION,
    )]


# --------------------------------------------------------------------------- links


def normalize_url(url: str) -> str:
    """Re-fang common defanging so URLs can be parsed: hxxp, [.], (.)."""
    url = re.sub(r"(?i)^hxxp", "http", url.strip())
    return url.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def _host(url: str) -> str:
    try:
        return (urlsplit(normalize_url(url)).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


_DOMAIN_IN_TEXT = re.compile(r"(?i)\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b")


def analyze_link(link: Link, cfg: AnalysisConfig) -> list[str]:
    """Return a list of reasons this link is suspicious (empty if clean)."""
    intel = load_intel()
    url = normalize_url(link.url)
    reasons: list[str] = []
    scheme = url.split(":", 1)[0].lower()
    if scheme in {"javascript", "data", "vbscript"}:
        return [f"{scheme}: URI scheme in link"]
    if scheme not in {"http", "https"}:
        return []

    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        return []

    if parts.username:
        reasons.append(f"userinfo '@' trick hides real host '{host}'")
    if _is_ip(host):
        reasons.append(f"raw IP address host {host}")
    if "xn--" in host:
        reasons.append(f"punycode host renders as '{decode_idna(host)}'")
    if registrable_domain(host) in intel["url_shorteners"]:
        reasons.append(f"URL shortener ({host}) hides final destination")
    tld = host.rsplit(".", 1)[-1]
    if tld in intel["suspicious_tlds"]:
        reasons.append(f"high-abuse TLD .{tld}")
    if host.count(".") >= 4:
        reasons.append(f"deeply nested subdomain ({host.count('.') + 1} labels)")

    lookalike = find_lookalike(host, cfg.protected_domains)
    if lookalike:
        reasons.append(f"lookalike of {lookalike.imitates} ({lookalike.technique}: {lookalike.detail})")

    path_ext = parts.path.rsplit(".", 1)[-1].lower() if "." in parts.path.rsplit("/", 1)[-1] else ""
    if path_ext in DANGEROUS_EXTENSIONS | CONTAINER_EXTENSIONS:
        reasons.append(f"direct download of .{path_ext} file")

    if link.source == "html" and link.text:
        shown = _DOMAIN_IN_TEXT.search(link.text)
        if shown:
            shown_reg = registrable_domain(shown.group(1).lower())
            if "." in shown_reg and shown_reg != registrable_domain(host):
                reasons.append(f"anchor text shows '{shown.group(1)}' but link goes to '{host}'")

    if scheme == "http" and reasons:
        reasons.append("unencrypted HTTP")
    return reasons


def check_links(email: ParsedEmail, cfg: AnalysisConfig) -> list[Finding]:
    findings: list[Finding] = []
    for link in email.links:
        is_form = link.text == "<form action>"
        reasons = analyze_link(link, cfg)
        if is_form:
            # Any form inside an email is a red flag: legitimate senders link to
            # their site instead of collecting input in the message body.
            reasons = ["form in message body submits user input off-message", *reasons]
        if not reasons:
            continue
        strong = any(k in r for r in reasons for k in ("lookalike", "anchor text", "userinfo", "URI scheme"))
        if is_form:
            sev, score, title = "critical", 40, "Embedded HTML form posts to external host"
        elif strong:
            sev, score, title = "high", 30, "Deceptive link"
        else:
            sev, score, title = "medium", 12, "Suspicious link"
        findings.append(Finding(
            "suspicious_link", title, sev, score,
            [f"URL: {link.url}"] + ([f"Text: {link.text}"] if link.text and not is_form else []) + reasons,
            T_CRED_HARVEST if (is_form or strong) else T_SPEAR_LINK,
        ))
    return findings


# --------------------------------------------------------------------------- attachments


def check_attachments(email: ParsedEmail, cfg: AnalysisConfig) -> list[Finding]:
    findings: list[Finding] = []
    for att in email.attachments:
        name = att.filename.lower().strip()
        parts = name.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        evidence = [f"{att.filename} ({att.content_type}, {att.size} bytes)", f"sha256: {att.sha256}"]

        if len(parts) > 2 and ext in DANGEROUS_EXTENSIONS and parts[-2] in set(DOCUMENT_MAGIC) | {"doc", "txt"}:
            findings.append(Finding(
                "attachment_double_extension", "Executable disguised with a double extension",
                "critical", 45, evidence, T_SPEAR_ATTACH))
        elif ext in DANGEROUS_EXTENSIONS:
            findings.append(Finding(
                "attachment_executable", f"Executable/script attachment (.{ext})",
                "critical", 45, evidence, T_SPEAR_ATTACH))
        elif ext in CONTAINER_EXTENSIONS:
            findings.append(Finding(
                "attachment_container", f"Archive/disk-image attachment (.{ext}) can bypass Mark-of-the-Web",
                "medium", 15, evidence, T_SPEAR_ATTACH))
        elif ext in MACRO_EXTENSIONS:
            findings.append(Finding(
                "attachment_macro", f"Macro-capable Office document (.{ext})",
                "high", 25, evidence, T_SPEAR_ATTACH))
        elif ext in SMUGGLING_EXTENSIONS:
            findings.append(Finding(
                "attachment_html_smuggling", f"HTML/SVG attachment (.{ext}) - HTML smuggling or local phishing page",
                "high", 25, evidence, T_SPEAR_ATTACH))

        if att.head.startswith(b"MZ") and ext not in {"exe", "dll", "scr", "com", "cpl"}:
            findings.append(Finding(
                "attachment_magic_mismatch", "Windows PE executable content behind a non-executable name",
                "critical", 45, evidence + ["file starts with 'MZ' (PE header)"], T_SPEAR_ATTACH))
        elif ext in DOCUMENT_MAGIC and att.size and not att.head.startswith(DOCUMENT_MAGIC[ext]):
            findings.append(Finding(
                "attachment_magic_mismatch", f"File content does not match .{ext} extension",
                "medium", 15, evidence + [f"leading bytes {att.head[:4]!r}"], T_SPEAR_ATTACH))
    return findings


# --------------------------------------------------------------------------- content


def _matches(patterns: list[str], text: str) -> list[str]:
    hits = []
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            hits.append(m.group(0))
    return hits


def _visible_text(email: ParsedEmail) -> str:
    html_text = re.sub(r"<[^>]+>", " ", email.html_body)
    return " ".join(f"{email.subject} {email.text_body} {html_text}".split())


def check_content(email: ParsedEmail, cfg: AnalysisConfig) -> list[Finding]:
    text = _visible_text(email)
    findings: list[Finding] = []

    urgency = _matches(URGENCY_PATTERNS, text)
    creds = _matches(CREDENTIAL_PATTERNS, text)
    if creds:
        findings.append(Finding(
            "credential_lure", "Credential-harvesting language", "medium", 15,
            [f"'{h}'" for h in creds], T_CRED_HARVEST))
    if len(urgency) >= 2 or (urgency and creds):
        findings.append(Finding(
            "urgency_pressure", "Urgency / fear pressure tactics", "low", 8,
            [f"'{h}'" for h in urgency]))

    bec = _matches(BEC_PATTERNS, text)
    if bec:
        has_mismatch = bool(email.reply_to) and any(
            registrable_domain(domain_of(r)) != registrable_domain(email.from_domain)
            for r in email.reply_to
        )
        findings.append(Finding(
            "bec_payment_lure", "Business Email Compromise (payment/gift-card) language",
            "high" if has_mismatch else "medium", 20 if has_mismatch else 12,
            [f"'{h}'" for h in bec]
            + (["combined with a Reply-To redirect"] if has_mismatch else []),
            T_IMPERSONATION,
        ))
    return findings


ALL_CHECKS = [
    check_authentication,
    check_sender_mismatch,
    check_display_name,
    check_sender_lookalike,
    check_links,
    check_attachments,
    check_content,
]


def run_all_checks(email: ParsedEmail, cfg: AnalysisConfig | None = None) -> list[Finding]:
    cfg = cfg or AnalysisConfig()
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(email, cfg))
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f.severity), -f.score))
    return findings


def sender_is_trusted(email: ParsedEmail, cfg: AnalysisConfig) -> bool:
    """Sender is a protected domain AND authenticated - used to dampen content-only signals."""
    return (
        is_legitimate(email.from_domain, cfg.protected_domains)
        and email.auth.dmarc == "pass"
    )
