"""Rule-based phishing indicators. Each rule inspects the parsed email (plus
derived auth-results / IOC data) and yields zero or more `Finding`s; nothing
here calls out to the network or an LLM, so the whole pipeline is scriptable
and fully unit-testable offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .authresults import AuthResultsSummary
from .iocs import (
    assess_attachment_filename,
    extract_urls,
    has_suspicious_tld,
    is_ip_literal_url,
    is_shortener,
    url_domain,
)
from .lookalike import brands, brands_mentioned_in, check_domain_against_brands
from .parser import ParsedEmail
from .scoring import Severity

URGENCY_PHRASES = [
    "verify your account",
    "account will be suspended",
    "account has been suspended",
    "confirm your password",
    "unusual activity",
    "unusual sign-in activity",
    "act immediately",
    "immediate action required",
    "urgent action required",
    "click here to avoid",
    "wire transfer",
    "gift card",
    "your account will be closed",
    "limited time",
    "failure to comply",
    "final notice",
]


@dataclass
class Finding:
    id: str
    severity: Severity
    title: str
    detail: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity.name,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
        }


def _domain_mismatch_findings(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    domains = {
        "from": email.from_domain or None,
        "reply_to": email.reply_to_domain,
        "return_path": email.return_path_domain,
    }
    present = {k: v for k, v in domains.items() if v}
    unique = set(present.values())
    if len(unique) > 1:
        if present.get("reply_to") and present["reply_to"] != present.get("from"):
            findings.append(
                Finding(
                    id="reply_to_mismatch",
                    severity=Severity.HIGH,
                    title="Reply-To domain differs from From domain",
                    detail=(
                        f"From domain is '{present.get('from')}' but replies are routed to "
                        f"'{present['reply_to']}' — a common BEC/phishing pattern where the "
                        "visible sender is spoofed but replies go to the attacker."
                    ),
                    evidence={"from_domain": present.get("from"), "reply_to_domain": present["reply_to"]},
                )
            )
        if present.get("return_path") and present["return_path"] != present.get("from"):
            findings.append(
                Finding(
                    id="return_path_mismatch",
                    severity=Severity.MEDIUM,
                    title="Return-Path domain differs from From domain",
                    detail=(
                        f"From domain is '{present.get('from')}' but bounces return to "
                        f"'{present['return_path']}'. Can be legitimate (bulk mail senders), "
                        "but combined with other findings it strengthens a spoofing case."
                    ),
                    evidence={"from_domain": present.get("from"), "return_path_domain": present["return_path"]},
                )
            )
    return findings


def _brand_impersonation_findings(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    mentioned = brands_mentioned_in(email.from_display_name)
    for brand in mentioned:
        official_domains = brands()[brand]
        if email.from_domain not in official_domains and not any(
            email.from_domain.endswith("." + d) for d in official_domains
        ):
            findings.append(
                Finding(
                    id="display_name_spoof",
                    severity=Severity.CRITICAL,
                    title=f"Display name impersonates '{brand}' but sender domain doesn't match",
                    detail=(
                        f"From header shows display name '{email.from_display_name}' (implying {brand}) "
                        f"but the actual sending address is on '{email.from_domain}', not "
                        f"{' or '.join(official_domains)}."
                    ),
                    evidence={"brand": brand, "from_domain": email.from_domain, "official_domains": official_domains},
                )
            )

    for match in check_domain_against_brands(email.from_domain):
        findings.append(
            Finding(
                id="lookalike_sender_domain",
                severity=Severity.HIGH,
                title=f"Sender domain looks like a typosquat of '{match.brand}'",
                detail=(
                    f"Sender domain '{match.matched_domain}' resembles {match.brand}'s official domain "
                    f"'{match.official_domain}' (technique: {match.technique})."
                ),
                evidence={
                    "brand": match.brand,
                    "official_domain": match.official_domain,
                    "matched_domain": match.matched_domain,
                    "technique": match.technique,
                },
            )
        )
    return findings


def _auth_findings(auth: AuthResultsSummary) -> list[Finding]:
    findings: list[Finding] = []
    if not auth.evaluated:
        findings.append(
            Finding(
                id="no_auth_results",
                severity=Severity.LOW,
                title="No Authentication-Results header found",
                detail=(
                    "The message carries no SPF/DKIM/DMARC verdict from a receiving mail server. "
                    "This is expected for locally-crafted test messages, but on a real message it "
                    "means authenticity could not be verified at the mail gateway."
                ),
            )
        )
        return findings

    failing = auth.failing_mechanisms()
    if failing:
        severity = Severity.CRITICAL if "dmarc" in failing else Severity.HIGH
        findings.append(
            Finding(
                id="auth_failure",
                severity=severity,
                title=f"Failed authentication check(s): {', '.join(m.upper() for m in failing)}",
                detail=(
                    f"SPF={auth.spf}, DKIM={auth.dkim}, DMARC={auth.dmarc}. A DMARC failure in "
                    "particular means the receiving server could not confirm the message came "
                    "from the domain it claims to be from."
                ),
                evidence={"spf": auth.spf, "dkim": auth.dkim, "dmarc": auth.dmarc},
            )
        )
    return findings


def _url_findings(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    urls = extract_urls(email.body_text) + extract_urls(email.body_html)
    urls += [link.href for link in email.html_links if link.href.lower().startswith(("http://", "https://"))]
    seen: set[str] = set()

    for url in urls:
        if url in seen:
            continue
        seen.add(url)

        if is_ip_literal_url(url):
            findings.append(
                Finding(
                    id="ip_literal_url",
                    severity=Severity.HIGH,
                    title="Link points directly to an IP address",
                    detail=f"URL '{url}' uses a raw IP address instead of a domain name, a common phishing/malware tell.",
                    evidence={"url": url},
                )
            )
        if is_shortener(url):
            findings.append(
                Finding(
                    id="url_shortener",
                    severity=Severity.MEDIUM,
                    title="Link uses a URL-shortening service",
                    detail=f"URL '{url}' hides its real destination behind a shortener ({url_domain(url)}).",
                    evidence={"url": url, "shortener_domain": url_domain(url)},
                )
            )
        if has_suspicious_tld(url):
            findings.append(
                Finding(
                    id="suspicious_tld",
                    severity=Severity.LOW,
                    title="Link uses a TLD commonly abused for phishing",
                    detail=f"URL '{url}' resolves under a top-level domain frequently used in phishing campaigns.",
                    evidence={"url": url},
                )
            )
        for match in check_domain_against_brands(url_domain(url)):
            findings.append(
                Finding(
                    id="lookalike_link_domain",
                    severity=Severity.HIGH,
                    title=f"Link domain looks like a typosquat of '{match.brand}'",
                    detail=(
                        f"URL '{url}' resembles {match.brand}'s official domain '{match.official_domain}' "
                        f"(technique: {match.technique})."
                    ),
                    evidence={"url": url, "brand": match.brand, "official_domain": match.official_domain},
                )
            )

    for link in email.html_links:
        text_domain = url_domain(link.text) if "." in link.text else ""
        href_domain = url_domain(link.href)
        if text_domain and href_domain and text_domain != href_domain:
            findings.append(
                Finding(
                    id="anchor_href_mismatch",
                    severity=Severity.HIGH,
                    title="Link text names one domain but points to another",
                    detail=(
                        f"Visible link text references '{text_domain}' but the actual href goes to "
                        f"'{href_domain}' — a classic disguised-link phishing tell."
                    ),
                    evidence={"displayed_domain": text_domain, "actual_href": link.href},
                )
            )

    return findings


def _attachment_findings(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    for attachment in email.attachments:
        if not attachment.filename:
            continue
        risk = assess_attachment_filename(attachment.filename)
        if risk.is_double_extension:
            findings.append(
                Finding(
                    id="double_extension_attachment",
                    severity=Severity.CRITICAL,
                    title="Attachment uses a disguised double extension",
                    detail=(
                        f"Attachment '{attachment.filename}' hides a dangerous '.{risk.extension}' "
                        "extension behind what looks like a document name."
                    ),
                    evidence={"filename": attachment.filename, "sha256": attachment.sha256},
                )
            )
        elif risk.is_dangerous:
            findings.append(
                Finding(
                    id="dangerous_attachment_extension",
                    severity=Severity.HIGH,
                    title="Attachment has an executable/script extension",
                    detail=f"Attachment '{attachment.filename}' has extension '.{risk.extension}', commonly used to deliver malware.",
                    evidence={"filename": attachment.filename, "sha256": attachment.sha256},
                )
            )
    return findings


def _urgency_findings(email: ParsedEmail) -> list[Finding]:
    haystack = f"{email.subject}\n{email.body_text}".lower()
    hits = [phrase for phrase in URGENCY_PHRASES if phrase in haystack]
    if not hits:
        return []
    return [
        Finding(
            id="urgency_language",
            severity=Severity.LOW,
            title="Message uses urgency/pressure language",
            detail=(
                "Detected phrase(s) commonly used to rush victims into acting without scrutiny: "
                + ", ".join(f"'{h}'" for h in hits)
            ),
            evidence={"phrases": hits},
        )
    ]


def run_all(email: ParsedEmail, auth: AuthResultsSummary) -> list[Finding]:
    findings: list[Finding] = []
    findings += _domain_mismatch_findings(email)
    findings += _brand_impersonation_findings(email)
    findings += _auth_findings(auth)
    findings += _url_findings(email)
    findings += _attachment_findings(email)
    findings += _urgency_findings(email)
    return findings
