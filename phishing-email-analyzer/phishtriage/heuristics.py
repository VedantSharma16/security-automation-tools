"""Rule-based phishing heuristics run against a ParsedEmail.

Each function looks for one pattern commonly used when triaging a
user-reported phishing email:

  - check_authentication: SPF/DKIM/DMARC failure, from the receiving
    gateway's own Authentication-Results header.
  - check_reply_to_mismatch: Reply-To domain differs from the From domain.
  - check_brand_impersonation: From display name references a known brand
    whose domain doesn't match the sender, or the sender domain is a
    close (Levenshtein-distance) typosquat of a known brand's domain.
  - check_links: raw-IP link hosts, known URL shorteners, and anchor
    text/href mismatches (link cloaking).
  - check_urgency_language: pressure/urgency phrasing in subject or body.
  - check_attachments: executable/macro-capable attachment extensions,
    including ones masquerading behind a document-looking name.

Findings are independent and composable, mirroring this repo's other
detector modules (e.g. log-triage-assistant/logtriage/detectors.py):
deterministic, evidence-carrying, and fed into `scoring.build_summary`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .auth import parse_authentication_results
from .parser import ParsedEmail
from .scoring import Severity

_DATA_DIR = Path(__file__).parent.parent / "data"

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly", "bl.ink",
}

_DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd", ".ps1", ".msi",
    ".docm", ".xlsm", ".pptm", ".hta", ".wsf", ".jse",
}

_URGENCY_PHRASES = [
    "verify your account", "account has been suspended", "act now",
    "act immediately", "urgent action required", "click immediately",
    "confirm your identity", "unusual activity", "account will be closed",
    "password will expire", "immediate action", "final notice",
    "limited time", "avoid suspension", "unauthorized access detected",
]

_IPV4_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$")
_URL_HOST_RE = re.compile(r"^[a-zA-Z]+://([^/:\s]+)")

_LOOKALIKE_MAX_DISTANCE = 2


def _load_known_brands() -> dict[str, list[str]]:
    path = _DATA_DIR / "known_brands.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _url_host(url: str) -> str:
    match = _URL_HOST_RE.match(url)
    return match.group(1).lower() if match else ""


def _root_domain(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


@dataclass
class Finding:
    type: str
    severity: Severity
    title: str
    description: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
        }


def check_authentication(email: ParsedEmail) -> list[Finding]:
    result = parse_authentication_results(email.authentication_results_raw)

    if not result.present:
        return [
            Finding(
                type="auth_results_missing",
                severity=Severity.LOW,
                title="No Authentication-Results header",
                description=(
                    "The receiving gateway did not stamp SPF/DKIM/DMARC results, "
                    "so sender authenticity could not be automatically verified."
                ),
                evidence={"authentication_results_raw": email.authentication_results_raw},
            )
        ]

    failing = result.failing_mechanisms
    if not failing:
        return []

    severity = Severity.CRITICAL if result.dmarc_fail else Severity.HIGH
    return [
        Finding(
            type="auth_failure",
            severity=severity,
            title=f"Sender authentication failed ({', '.join(failing)})",
            description=(
                "One or more of SPF, DKIM, and DMARC failed verification, "
                "indicating the message likely did not originate from the "
                "domain it claims to be from."
            ),
            evidence={"spf": result.spf, "dkim": result.dkim, "dmarc": result.dmarc, "failing": failing},
        )
    ]


def check_reply_to_mismatch(email: ParsedEmail) -> list[Finding]:
    if not email.reply_to_domain or not email.from_domain:
        return []
    if email.reply_to_domain == email.from_domain:
        return []
    return [
        Finding(
            type="reply_to_mismatch",
            severity=Severity.MEDIUM,
            title="Reply-To domain differs from From domain",
            description=(
                "Replies are routed to a different domain than the message claims "
                "to be sent from -- a common tactic to intercept victim responses "
                "while the From header still looks legitimate."
            ),
            evidence={"from_domain": email.from_domain, "reply_to_domain": email.reply_to_domain},
        )
    ]


def check_brand_impersonation(
    email: ParsedEmail, known_brands: dict[str, list[str]] | None = None
) -> list[Finding]:
    known_brands = known_brands if known_brands is not None else _load_known_brands()
    findings: list[Finding] = []
    display_name = email.from_display_name.lower()
    from_domain = email.from_domain

    if not from_domain:
        return findings

    if display_name:
        for brand, legit_domains in known_brands.items():
            if brand not in display_name:
                continue
            if any(from_domain == d or from_domain.endswith("." + d) for d in legit_domains):
                continue
            findings.append(
                Finding(
                    type="brand_display_name_mismatch",
                    severity=Severity.HIGH,
                    title=f"Display name impersonates '{brand}' but sender domain does not match",
                    description=(
                        f"The From display name references '{brand}', but the sending "
                        f"domain '{from_domain}' is not one of its known domains "
                        f"({', '.join(legit_domains)})."
                    ),
                    evidence={"brand": brand, "display_name": email.from_display_name, "from_domain": from_domain},
                )
            )
            break  # one brand match is enough evidence; avoid duplicate findings

    for brand, legit_domains in known_brands.items():
        for legit_domain in legit_domains:
            if from_domain == legit_domain or from_domain.endswith("." + legit_domain):
                continue
            distance = _levenshtein(from_domain, legit_domain)
            if 0 < distance <= _LOOKALIKE_MAX_DISTANCE and _root_domain(from_domain) != _root_domain(legit_domain):
                findings.append(
                    Finding(
                        type="lookalike_sender_domain",
                        severity=Severity.HIGH,
                        title=f"Sender domain closely resembles known brand domain '{legit_domain}'",
                        description=(
                            f"Sender domain '{from_domain}' is only {distance} character(s) "
                            f"different from the legitimate '{brand}' domain '{legit_domain}' "
                            "-- a classic typosquat/lookalike pattern."
                        ),
                        evidence={
                            "brand": brand,
                            "from_domain": from_domain,
                            "legit_domain": legit_domain,
                            "edit_distance": distance,
                        },
                    )
                )
                return findings  # one strong match is sufficient evidence

    return findings


def check_links(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    ip_literal_links: list[str] = []
    shortener_links: list[str] = []
    mismatched_links: list[dict] = []

    for link in email.links:
        host = _url_host(link.href)
        if not host:
            continue

        if _IPV4_HOST_RE.match(host):
            ip_literal_links.append(link.href)

        if host in _URL_SHORTENERS:
            shortener_links.append(link.href)

        anchor_host = _url_host(link.anchor_text)
        if anchor_host and _root_domain(anchor_host) != _root_domain(host):
            mismatched_links.append({"anchor_text": link.anchor_text, "href": link.href})

    if ip_literal_links:
        findings.append(
            Finding(
                type="ip_literal_link",
                severity=Severity.HIGH,
                title="Link points to a raw IP address",
                description=(
                    "One or more links use a numeric IP address instead of a domain "
                    "name, unusual for legitimate mail and common in phishing kits."
                ),
                evidence={"links": ip_literal_links},
            )
        )

    if shortener_links:
        findings.append(
            Finding(
                type="url_shortener",
                severity=Severity.MEDIUM,
                title="Link uses a URL shortening service",
                description=(
                    "Shortened URLs hide the true destination domain until clicked, "
                    "a common way to bypass quick visual inspection."
                ),
                evidence={"links": shortener_links},
            )
        )

    if mismatched_links:
        findings.append(
            Finding(
                type="mismatched_anchor_text",
                severity=Severity.CRITICAL,
                title="Link text does not match its actual destination",
                description=(
                    "The visible link text displays one domain while the underlying "
                    "href points to a different one -- classic link-cloaking used to "
                    "disguise a malicious destination."
                ),
                evidence={"links": mismatched_links},
            )
        )

    return findings


def check_urgency_language(email: ParsedEmail) -> list[Finding]:
    haystack = f"{email.subject}\n{email.body_text}\n{email.body_html}".lower()
    matched = [phrase for phrase in _URGENCY_PHRASES if phrase in haystack]
    if not matched:
        return []
    return [
        Finding(
            type="urgency_language",
            severity=Severity.LOW,
            title="Message uses urgency/pressure language",
            description=(
                "The message uses language designed to pressure the recipient into "
                "acting quickly without scrutiny, a hallmark of social engineering."
            ),
            evidence={"matched_phrases": matched},
        )
    ]


def check_attachments(email: ParsedEmail) -> list[Finding]:
    dangerous: list[str] = []
    masquerading: list[str] = []

    for attachment in email.attachments:
        name = (attachment.filename or "").lower()
        if not name:
            continue
        suffixes = Path(name).suffixes
        if not suffixes or suffixes[-1] not in _DANGEROUS_EXTENSIONS:
            continue
        dangerous.append(attachment.filename)
        if len(suffixes) >= 2 and suffixes[-2] not in _DANGEROUS_EXTENSIONS:
            masquerading.append(attachment.filename)

    if not dangerous:
        return []

    return [
        Finding(
            type="dangerous_attachment",
            severity=Severity.CRITICAL,
            title="Attachment has a potentially executable extension",
            description=(
                "One or more attachments use file extensions capable of executing "
                "code or macros on the recipient's machine."
                + (
                    " Some hide this behind a document-looking double extension "
                    "(e.g. invoice.pdf.exe)."
                    if masquerading
                    else ""
                )
            ),
            evidence={"attachments": dangerous, "masquerading_as_document": masquerading},
        )
    ]


def run_all_heuristics(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_authentication(email))
    findings.extend(check_reply_to_mismatch(email))
    findings.extend(check_brand_impersonation(email))
    findings.extend(check_links(email))
    findings.extend(check_urgency_language(email))
    findings.extend(check_attachments(email))
    return findings
