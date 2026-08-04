"""Rule-based heuristics over the email's visible text, sender identity, and attachments.

These are the classic social-engineering tells: manufactured urgency, requests
for sensitive information, generic (non-personalized) greetings, a display name
that claims to be a brand its address domain doesn't match, and attachments with
dangerous or disguised (double) extensions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .brands import is_legit_domain_for_brand, matching_brand
from .parser import Attachment

URGENCY_PHRASES = (
    "act now", "act immediately", "urgent action required", "account will be suspended",
    "account has been suspended", "account has been limited", "verify your account",
    "confirm your identity", "unusual activity", "unauthorized access detected",
    "within 24 hours", "immediate action required", "click here immediately",
    "failure to comply", "final notice", "your account will be closed",
    "suspicious login attempt", "expires today", "avoid suspension",
)

SENSITIVE_INFO_KEYWORDS = (
    "social security number", "ssn", "credit card number", "cvv",
    "wire transfer", "gift card", "bank account number", "routing number",
    "one-time password", "one time passcode", "otp code", "password reset link",
    "confirm your password", "enter your password",
)

GENERIC_GREETINGS = (
    "dear customer", "dear user", "dear valued customer", "dear account holder",
    "dear sir/madam", "dear member", "dear email user",
)

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".jar", ".msi", ".lnk", ".gadget",
}

_DOUBLE_EXTENSION_RE = re.compile(
    r"\.\w{2,5}\.(exe|scr|js|jse|vbs|vbe|bat|cmd|hta|jar|ps1|wsf|msi|lnk)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ContentFindings:
    matched_urgency_phrases: tuple[str, ...] = field(default_factory=tuple)
    matched_sensitive_info_keywords: tuple[str, ...] = field(default_factory=tuple)
    matched_generic_greeting: str | None = None
    weight: int = 0

    def as_dict(self) -> dict:
        return {
            "matched_urgency_phrases": list(self.matched_urgency_phrases),
            "matched_sensitive_info_keywords": list(self.matched_sensitive_info_keywords),
            "matched_generic_greeting": self.matched_generic_greeting,
            "weight": self.weight,
        }


@dataclass(frozen=True)
class SenderFinding:
    from_display: str
    from_domain: str
    claimed_brand: str | None = None
    is_impersonation: bool = False
    reasons: tuple[str, ...] = field(default_factory=tuple)
    weight: int = 0

    def as_dict(self) -> dict:
        return {
            "from_display": self.from_display,
            "from_domain": self.from_domain,
            "claimed_brand": self.claimed_brand,
            "is_impersonation": self.is_impersonation,
            "reasons": list(self.reasons),
            "weight": self.weight,
        }


@dataclass(frozen=True)
class AttachmentFinding:
    filename: str | None
    content_type: str
    is_dangerous_extension: bool = False
    is_double_extension: bool = False
    reasons: tuple[str, ...] = field(default_factory=tuple)
    weight: int = 0

    def as_dict(self) -> dict:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "is_dangerous_extension": self.is_dangerous_extension,
            "is_double_extension": self.is_double_extension,
            "reasons": list(self.reasons),
            "weight": self.weight,
        }


def analyze_content(subject: str, visible_text: str) -> ContentFindings:
    lowered = f"{subject}\n{visible_text}".lower()

    matched_urgency = tuple(p for p in URGENCY_PHRASES if p in lowered)
    matched_sensitive = tuple(k for k in SENSITIVE_INFO_KEYWORDS if k in lowered)
    matched_greeting = next((g for g in GENERIC_GREETINGS if g in lowered), None)

    weight = min(24, len(matched_urgency) * 8) + min(30, len(matched_sensitive) * 15)
    if matched_greeting:
        weight += 5

    return ContentFindings(
        matched_urgency_phrases=matched_urgency,
        matched_sensitive_info_keywords=matched_sensitive,
        matched_generic_greeting=matched_greeting,
        weight=weight,
    )


def analyze_sender(from_display: str, from_domain: str) -> SenderFinding:
    brand = matching_brand(from_display) if from_display else None
    if brand is None or not from_domain:
        return SenderFinding(from_display=from_display, from_domain=from_domain)

    if is_legit_domain_for_brand(brand, from_domain):
        return SenderFinding(
            from_display=from_display, from_domain=from_domain, claimed_brand=brand
        )

    reason = (
        f"display name {from_display!r} claims to be '{brand}', but the sending "
        f"address domain {from_domain!r} is not a known {brand} domain"
    )
    return SenderFinding(
        from_display=from_display,
        from_domain=from_domain,
        claimed_brand=brand,
        is_impersonation=True,
        reasons=(reason,),
        weight=25,
    )


def analyze_attachments(attachments: tuple[Attachment, ...]) -> list[AttachmentFinding]:
    findings = []
    for att in attachments:
        filename = att.filename or ""
        lower_name = filename.lower()
        reasons: list[str] = []
        weight = 0

        is_double_ext = bool(_DOUBLE_EXTENSION_RE.search(lower_name))
        is_dangerous = any(lower_name.endswith(ext) for ext in DANGEROUS_EXTENSIONS)

        if is_double_ext:
            reasons.append(
                f"attachment {filename!r} uses a disguised double extension "
                "(e.g. 'invoice.pdf.exe') to hide its true, executable type"
            )
            weight += 35
        elif is_dangerous:
            reasons.append(
                f"attachment {filename!r} has a potentially dangerous executable/script extension"
            )
            weight += 30

        findings.append(
            AttachmentFinding(
                filename=att.filename,
                content_type=att.content_type,
                is_dangerous_extension=is_dangerous,
                is_double_extension=is_double_ext,
                reasons=tuple(reasons),
                weight=weight,
            )
        )
    return findings
