"""Independent, explainable phishing detectors.

Each detector inspects one aspect of an :class:`AnalysisContext` and returns
zero or more :class:`Finding` objects. Every finding carries the evidence that
triggered it plus a MITRE ATT&CK technique, so the report stays auditable and
can be pasted straight into a ticket.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .content import BodyAnalysis, analyze_body
from .domains import DEFAULT_PROTECTED_BRANDS, find_lookalike, registrable_domain
from .headers import AuthResults, Hop, originating_ip, parse_auth_results, parse_received_chain
from .parser import ParsedEmail

SEVERITY_WEIGHTS = {"LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 50}

T_SPEARPHISH_LINK = "T1566.002"
T_SPEARPHISH_ATTACH = "T1566.001"
T_PHISHING = "T1566"
T_IMPERSONATION = "T1656"
T_HTML_SMUGGLING = "T1027.006"
T_MASQUERADE_EXT = "T1036.007"
T_PROMPT_INJECTION = "AML.T0051.001"  # MITRE ATLAS: LLM Prompt Injection (indirect)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
    "support", "rest", "cam", "icu", "monster", "quest", "sbs", "cfd",
}
EXECUTABLE_EXTS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "ps1", "msi", "dll", "cpl", "jar", "lnk", "reg", "chm", "iso", "img", "vhd", "vhdx", "one",
}
MACRO_EXTS = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "xls", "doc"}
ARCHIVE_EXTS = {"zip", "rar", "7z", "gz", "tar", "cab", "ace", "arj"}
HTML_EXTS = {"html", "htm", "shtml", "svg", "xhtml"}
DECOY_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "jpeg", "png", "rtf"}
_DOMAIN_IN_TEXT_RE = re.compile(r"(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})\b")
# Leading bytes for formats whose declared type/extension is commonly spoofed.
MAGIC_SIGNATURES = {b"MZ": "pe_executable", b"PK\x03\x04": "zip", b"%PDF": "pdf", b"\xd0\xcf\x11\xe0": "ole2"}


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    technique: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity,
            "technique": self.technique,
            "evidence": self.evidence,
        }


@dataclass
class AnalysisContext:
    email: ParsedEmail
    auth: AuthResults
    hops: list[Hop]
    body: BodyAnalysis
    brands: dict[str, list[str]]

    @property
    def origin_ip(self) -> str:
        return originating_ip(self.hops)


def build_context(
    email: ParsedEmail,
    brands: dict[str, list[str]] | None = None,
    trusted_authserv_ids: list[str] | None = None,
) -> AnalysisContext:
    return AnalysisContext(
        email=email,
        auth=parse_auth_results(email, trusted_authserv_ids),
        hops=parse_received_chain(email),
        body=analyze_body(email.text_body, email.html_body),
        brands=brands or DEFAULT_PROTECTED_BRANDS,
    )


# --------------------------------------------------------------------------- header rules


def detect_auth_failures(ctx: AnalysisContext) -> list[Finding]:
    a = ctx.auth
    findings = []
    if a.dmarc in ("fail", "reject", "quarantine"):
        findings.append(Finding(
            "auth.dmarc_fail", "DMARC failed for the From: domain", "HIGH", T_IMPERSONATION,
            [f"dmarc={a.dmarc} (authserv-id: {a.authserv_id or 'unknown'})",
             f"From domain: {ctx.email.sender.domain}"],
        ))
    if a.spf in ("fail", "softfail", "permerror"):
        findings.append(Finding(
            "auth.spf_fail", f"SPF {a.spf}: sending host not authorized", "MEDIUM" if a.spf == "softfail" else "HIGH",
            T_IMPERSONATION, [f"spf={a.spf}", f"smtp.mailfrom domain: {a.spf_domain or ctx.email.return_path_domain or '?'}",
                              f"originating IP: {ctx.origin_ip or 'unknown'}"],
        ))
    if a.dkim in ("fail", "permerror"):
        findings.append(Finding(
            "auth.dkim_fail", "DKIM signature failed verification", "MEDIUM", T_IMPERSONATION,
            [f"dkim={a.dkim}", f"signing domain(s): {', '.join(a.dkim_domains) or 'unknown'}"],
        ))
    if a.source == "absent":
        findings.append(Finding(
            "auth.no_results", "No authentication results present", "LOW", T_PHISHING,
            ["Message carries neither Authentication-Results nor Received-SPF; sender cannot be verified"],
        ))
    return findings


def detect_reply_to_mismatch(ctx: AnalysisContext) -> list[Finding]:
    from_reg = registrable_domain(ctx.email.sender.domain)
    findings = []
    for rt in ctx.email.reply_to:
        if rt.domain and registrable_domain(rt.domain) != from_reg:
            findings.append(Finding(
                "header.reply_to_mismatch", "Reply-To diverts replies to a different domain", "MEDIUM", T_PHISHING,
                [f"From: {ctx.email.sender.address}", f"Reply-To: {rt.address}"],
            ))
    rp = ctx.email.return_path_domain
    if rp and from_reg and registrable_domain(rp) != from_reg and ctx.auth.dmarc != "pass":
        findings.append(Finding(
            "header.return_path_mismatch", "Envelope sender (Return-Path) does not align with From:", "LOW",
            T_IMPERSONATION, [f"From domain: {from_reg}", f"Return-Path domain: {registrable_domain(rp)}"],
        ))
    return findings


def detect_display_name_spoof(ctx: AnalysisContext) -> list[Finding]:
    sender = ctx.email.sender
    name = sender.display_name.lower()
    findings = []
    from_reg = registrable_domain(sender.domain)

    if "@" in name:
        embedded = name.split("@", 1)[1].split()[0].strip(">)\"'.,")
        if embedded and registrable_domain(embedded) != from_reg:
            findings.append(Finding(
                "header.display_name_address", "Display name contains a different email address", "HIGH",
                T_IMPERSONATION, [f"Display name: {sender.display_name!r}", f"Actual address: {sender.address}"],
            ))
            return findings

    compact = "".join(ch for ch in name if ch.isalnum())
    for brand, legit in ctx.brands.items():
        if brand in compact and from_reg not in legit:
            findings.append(Finding(
                "header.display_name_brand", f"Display name claims to be '{brand}' but sender domain is not theirs",
                "HIGH", T_IMPERSONATION,
                [f"Display name: {sender.display_name!r}", f"Sender domain: {from_reg}",
                 f"Legitimate domains: {', '.join(legit)}"],
            ))
            break
    return findings


def detect_lookalike_sender(ctx: AnalysisContext) -> list[Finding]:
    match = find_lookalike(ctx.email.sender.domain, ctx.brands) if ctx.email.sender.domain else None
    if not match:
        return []
    return [Finding(
        "header.lookalike_sender", f"Sender domain impersonates '{match.brand}' ({match.technique})", "HIGH",
        T_IMPERSONATION, [f"From: {ctx.email.sender.address}", match.detail],
    )]


# --------------------------------------------------------------------------- link rules


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def detect_link_issues(ctx: AnalysisContext) -> list[Finding]:
    findings = []
    for link in ctx.body.links:
        host = link.host
        if not host:
            continue
        reg = registrable_domain(host)

        # Visible anchor text shows one domain, href goes to another.
        if link.source == "html_anchor" and link.text:
            shown_m = _DOMAIN_IN_TEXT_RE.search(link.text.lower())
            shown = shown_m.group(1) if shown_m else ""
            if shown and registrable_domain(shown) != reg:
                findings.append(Finding(
                    "link.text_href_mismatch", "Link text displays a different domain than its real target", "HIGH",
                    T_SPEARPHISH_LINK, [f"Displayed: {link.text}", f"Actual target: {link.url}"],
                ))

        if _is_ip_host(host):
            findings.append(Finding("link.ip_host", "Link points to a raw IP address", "MEDIUM", T_SPEARPHISH_LINK,
                                    [link.url]))
        if reg in URL_SHORTENERS:
            findings.append(Finding("link.shortener", "Link uses a URL shortener that hides its destination", "LOW",
                                    T_SPEARPHISH_LINK, [link.url]))
        if "xn--" in host:
            findings.append(Finding("link.punycode", "Link host uses punycode (IDN)", "MEDIUM", T_SPEARPHISH_LINK,
                                    [link.url]))
        tld = host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            findings.append(Finding("link.suspicious_tld", f"Link uses high-abuse TLD .{tld}", "LOW",
                                    T_SPEARPHISH_LINK, [link.url]))
        if "@" in link.url.split("//", 1)[-1].split("/", 1)[0]:
            findings.append(Finding("link.userinfo_obfuscation", "URL hides real host behind user-info ('@') trick",
                                    "HIGH", T_SPEARPHISH_LINK, [link.url]))
        match = find_lookalike(host, ctx.brands)
        if match:
            findings.append(Finding("link.lookalike_domain", f"Link domain impersonates '{match.brand}' ({match.technique})",
                                    "HIGH", T_SPEARPHISH_LINK, [link.url, match.detail]))
    return _dedupe(findings)


def detect_credential_form(ctx: AnalysisContext) -> list[Finding]:
    if not ctx.body.form_actions:
        return []
    return [Finding(
        "content.embedded_form", "Email body contains an HTML form (inline credential harvesting)", "HIGH",
        T_SPEARPHISH_LINK, [f"form action: {a}" for a in ctx.body.form_actions],
    )]


def detect_urgency(ctx: AnalysisContext) -> list[Finding]:
    hits = ctx.body.urgency_hits
    if len(hits) < 2:
        return []
    return [Finding(
        "content.urgency_lure", "Social-engineering pressure language", "MEDIUM" if len(hits) >= 3 else "LOW",
        T_PHISHING, [f"matched: {h!r}" for h in hits[:6]],
    )]


def detect_hidden_content(ctx: AnalysisContext) -> list[Finding]:
    findings = []
    if ctx.body.injection_hits:
        findings.append(Finding(
            "content.prompt_injection", "Text addressed to AI assistants (indirect prompt injection)", "HIGH",
            T_PROMPT_INJECTION, [f"matched: {h!r}" for h in ctx.body.injection_hits[:6]]
            + (["instructions are inside CSS-hidden text"] if ctx.body.hidden_text else []),
        ))
    hidden = ctx.body.hidden_text
    if len(hidden) >= 40:
        findings.append(Finding(
            "content.hidden_text", "Substantial CSS-hidden text (filter evasion / AI-targeted payload)", "MEDIUM",
            T_PHISHING, [f"{len(hidden)} hidden characters", f"excerpt: {hidden[:120]!r}"],
        ))
    return findings


# --------------------------------------------------------------------------- attachment rules


def _magic_kind(magic: bytes) -> str:
    for sig, kind in MAGIC_SIGNATURES.items():
        if magic.startswith(sig):
            return kind
    return ""


def detect_attachment_issues(ctx: AnalysisContext) -> list[Finding]:
    findings = []
    for att in ctx.email.attachments:
        name = att.filename.lower().strip()
        suffixes = [s.lstrip(".") for s in PurePosixPath(name).suffixes]
        ext = suffixes[-1] if suffixes else ""
        ev = [f"{att.filename} ({att.content_type}, {att.size} bytes)", f"sha256: {att.sha256}"]

        if len(suffixes) >= 2 and suffixes[-2] in DECOY_EXTS and ext in EXECUTABLE_EXTS | HTML_EXTS:
            findings.append(Finding("attachment.double_extension", "Double extension disguises file type", "CRITICAL",
                                    T_MASQUERADE_EXT, ev))
        elif ext in EXECUTABLE_EXTS:
            findings.append(Finding("attachment.executable", f"Executable / script attachment (.{ext})", "CRITICAL",
                                    T_SPEARPHISH_ATTACH, ev))
        if ext in HTML_EXTS:
            findings.append(Finding("attachment.html", "HTML/SVG attachment (HTML smuggling or local phishing page)",
                                    "HIGH", T_HTML_SMUGGLING, ev))
        if ext in MACRO_EXTS:
            findings.append(Finding("attachment.macro_office", f"Macro-capable Office document (.{ext})", "HIGH",
                                    T_SPEARPHISH_ATTACH, ev))
        if ext in ARCHIVE_EXTS:
            findings.append(Finding("attachment.archive", f"Archive attachment (.{ext}) can conceal payloads", "MEDIUM",
                                    T_SPEARPHISH_ATTACH, ev))

        kind = _magic_kind(att.magic)
        if kind == "pe_executable" and ext not in EXECUTABLE_EXTS:
            findings.append(Finding("attachment.magic_mismatch", "File content is a Windows executable despite its name",
                                    "CRITICAL", T_MASQUERADE_EXT, ev + ["magic bytes: MZ"]))
        elif kind == "zip" and ext in {"pdf", "txt", "jpg", "png"}:
            findings.append(Finding("attachment.magic_mismatch", "File content does not match its extension", "HIGH",
                                    T_MASQUERADE_EXT, ev + ["magic bytes: PK (zip container)"]))
    return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.rule, tuple(f.evidence))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


ALL_DETECTORS = [
    detect_auth_failures,
    detect_reply_to_mismatch,
    detect_display_name_spoof,
    detect_lookalike_sender,
    detect_link_issues,
    detect_credential_form,
    detect_urgency,
    detect_hidden_content,
    detect_attachment_issues,
]


def run_all_detectors(ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    for detector in ALL_DETECTORS:
        findings.extend(detector(ctx))
    order = list(SEVERITY_WEIGHTS)
    return sorted(findings, key=lambda f: -order.index(f.severity))
