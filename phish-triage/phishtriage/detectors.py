"""Combine header, URL, attachment, and body-text heuristics into structured Findings.

Each detector looks for one pattern from a standard phishing triage playbook,
and (where applicable) maps it to a MITRE ATT&CK technique so the report
speaks the same language incident responders already use:

  - AuthFailureDetector       -- SPF/DKIM/DMARC fail, or no auth results at all.
  - DisplayNameSpoofDetector  -- From display name claims a brand the sending
    domain doesn't belong to (T1656 Impersonation).
  - ReplyToMismatchDetector   -- Reply-To silently redirects responses to a
    different domain than the visible sender (T1656 Impersonation).
  - SuspiciousUrlDetector     -- links with IP-literal hosts, shorteners,
    punycode, userinfo tricks, or brand-lookalike domains
    (T1566.002 Spearphishing Link).
  - LinkTextMismatchDetector  -- an anchor's visible text names one domain but
    the href points somewhere else (T1566.002 Spearphishing Link).
  - DangerousAttachmentDetector -- executable/script/macro attachments, or a
    double extension hiding one (T1566.001 Spearphishing Attachment).
  - UrgencyLanguageDetector   -- body text using urgency/credential-harvest
    phrasing commonly paired with a malicious link (T1598 Phishing for
    Information).

Detectors are independent; `run_all_detectors` just runs each and flattens
the results in a fixed, reproducible order.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .attachments import classify_attachment
from .headers import (
    display_name_impersonation,
    domain_of,
    parse_auth_results,
    reply_to_mismatch,
    return_path_mismatch,
)
from .parser import Message
from .scoring import Severity
from .urls import analyze_urls, extract_href_text_pairs, extract_urls, find_domain_like, get_host

URGENCY_PHRASES = [
    r"verify your account",
    r"confirm your (?:password|identity|account)",
    r"account (?:has been |will be )?suspend",
    r"unusual (?:sign-?in|login) activity",
    r"click here immediately",
    r"urgent action required",
    r"account will be (?:closed|locked|terminated)",
    r"update your (?:payment|billing) (?:information|details)",
    r"security alert",
    r"limited time",
    r"failure to (?:comply|respond|verify)",
]
URGENCY_RE = re.compile("|".join(URGENCY_PHRASES), re.IGNORECASE)


@dataclass
class Finding:
    type: str
    severity: Severity
    title: str
    description: str
    evidence: dict
    attack_technique: str | None = None

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "attack_technique": self.attack_technique,
        }


def detect_auth_failure(msg: Message) -> list[Finding]:
    results = parse_auth_results(msg.auth_results_raw)
    if results.none_present():
        return [
            Finding(
                type="auth_results_missing",
                severity=Severity.LOW,
                title="No Authentication-Results header present",
                description=(
                    "The message carries no SPF/DKIM/DMARC verdict from the receiving "
                    "mail server, so sender authenticity could not be verified in transit."
                ),
                evidence={"from": msg.from_addr},
            )
        ]
    if results.any_failed():
        return [
            Finding(
                type="auth_failure",
                severity=Severity.HIGH,
                title="SPF/DKIM/DMARC authentication failed",
                description=(
                    "The message failed one or more sender-authentication checks, "
                    "meaning it may not actually originate from the claimed sending domain."
                ),
                evidence={
                    "spf": results.spf,
                    "dkim": results.dkim,
                    "dmarc": results.dmarc,
                    "from": msg.from_addr,
                },
                attack_technique="T1656 (Impersonation)",
            )
        ]
    return []


def detect_display_name_spoof(msg: Message) -> list[Finding]:
    brand = display_name_impersonation(msg.from_display, msg.from_addr)
    if not brand:
        return []
    return [
        Finding(
            type="display_name_spoof",
            severity=Severity.CRITICAL,
            title=f"Display name impersonates {brand}",
            description=(
                f"The From display name ('{msg.from_display}') references {brand}, but "
                f"the sending address's domain ({domain_of(msg.from_addr)}) does not "
                "belong to that brand."
            ),
            evidence={"from_display": msg.from_display, "from_addr": msg.from_addr, "brand": brand},
            attack_technique="T1656 (Impersonation)",
        )
    ]


def detect_reply_to_mismatch(msg: Message) -> list[Finding]:
    findings = []
    if reply_to_mismatch(msg.from_addr, msg.reply_to_addr):
        findings.append(
            Finding(
                type="reply_to_mismatch",
                severity=Severity.MEDIUM,
                title="Reply-To domain differs from From domain",
                description=(
                    "Replies to this message are silently redirected to a different "
                    "domain than the one it claims to be sent from -- a common tactic to "
                    "route victim responses away from the impersonated organization."
                ),
                evidence={"from_addr": msg.from_addr, "reply_to_addr": msg.reply_to_addr},
                attack_technique="T1656 (Impersonation)",
            )
        )
    if return_path_mismatch(msg.from_addr, msg.return_path_addr):
        findings.append(
            Finding(
                type="return_path_mismatch",
                severity=Severity.LOW,
                title="Return-Path domain closely resembles but does not match From domain",
                description=(
                    "The bounce address (Return-Path) domain is a near-miss for the "
                    "From domain, consistent with a spoofed or typosquatted sending "
                    "infrastructure rather than an unrelated legitimate mail platform."
                ),
                evidence={"from_addr": msg.from_addr, "return_path_addr": msg.return_path_addr},
            )
        )
    return findings


def detect_suspicious_urls(msg: Message) -> list[Finding]:
    urls = extract_urls(msg.body_text, msg.body_html)
    flagged = analyze_urls(urls)
    findings = []
    for item in flagged:
        severity = Severity.HIGH if any("impersonate" in r for r in item.reasons) else Severity.MEDIUM
        findings.append(
            Finding(
                type="suspicious_url",
                severity=severity,
                title=f"Suspicious link: {item.host}",
                description=f"Link flagged for: {', '.join(item.reasons)}.",
                evidence={"url": item.url, "host": item.host, "reasons": item.reasons},
                attack_technique="T1566.002 (Spearphishing Link)",
            )
        )
    return findings


def detect_link_text_mismatch(msg: Message) -> list[Finding]:
    findings = []
    for href, visible_text in extract_href_text_pairs(msg.body_html):
        visible_host = find_domain_like(visible_text)
        href_host = get_host(href)
        if not visible_host or not href_host or visible_host == href_host:
            continue
        if href_host.endswith("." + visible_host) or visible_host.endswith("." + href_host):
            continue  # href is a subdomain of the displayed domain (or vice versa) -- not a mismatch
        findings.append(
            Finding(
                type="link_text_mismatch",
                severity=Severity.HIGH,
                title="Link text does not match its destination",
                description=(
                    f"Displayed link text references '{visible_host}' but the link "
                    f"actually points to '{href_host}'."
                ),
                evidence={"visible_text": visible_text, "href": href},
                attack_technique="T1566.002 (Spearphishing Link)",
            )
        )
    return findings


def detect_dangerous_attachments(msg: Message) -> list[Finding]:
    findings = []
    for attachment in msg.attachments:
        reasons = classify_attachment(attachment)
        if reasons:
            findings.append(
                Finding(
                    type="dangerous_attachment",
                    severity=Severity.CRITICAL,
                    title=f"Risky attachment: {attachment.filename}",
                    description=", ".join(reasons),
                    evidence={
                        "filename": attachment.filename,
                        "content_type": attachment.content_type,
                        "size_bytes": attachment.size_bytes,
                        "reasons": reasons,
                    },
                    attack_technique="T1566.001 (Spearphishing Attachment)",
                )
            )
    return findings


def detect_urgency_language(msg: Message) -> list[Finding]:
    combined = f"{msg.subject}\n{msg.body_text}\n{msg.body_html}"
    matches = sorted(set(m.group(0).lower() for m in URGENCY_RE.finditer(combined)))
    if not matches:
        return []
    return [
        Finding(
            type="urgency_language",
            severity=Severity.LOW,
            title="Urgency / credential-harvest phrasing detected",
            description=(
                "The message uses language commonly paired with phishing and "
                "credential-harvesting lures, pressuring quick action."
            ),
            evidence={"matched_phrases": matches},
            attack_technique="T1598 (Phishing for Information)",
        )
    ]


DETECTORS = [
    detect_auth_failure,
    detect_display_name_spoof,
    detect_reply_to_mismatch,
    detect_suspicious_urls,
    detect_link_text_mismatch,
    detect_dangerous_attachments,
    detect_urgency_language,
]


def run_all_detectors(msg: Message) -> list[Finding]:
    findings: list[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(msg))
    return findings
