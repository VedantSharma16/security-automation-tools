"""Regex signatures for well-known secret formats.

Each Signature matches a specific credential format from a specific
provider (or a generic assignment pattern) and carries a fixed severity.
This is the high-precision detection path; `entropy.py` provides a
lower-precision fallback for secrets that don't match any known format.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    id: str
    pattern: "re.Pattern"
    severity: str
    description: str
    # Which regex group holds the secret value itself (for redaction and
    # allowlist checks). Group 0 (the whole match) is used when None.
    value_group: int | None = None

    def secret_value(self, match: "re.Match") -> str:
        group = self.value_group if self.value_group is not None else 0
        return match.group(group)


def _sig(id, pattern, severity, description, value_group=None, flags=0):
    return Signature(
        id=id,
        pattern=re.compile(pattern, flags),
        severity=severity,
        description=description,
        value_group=value_group,
    )


# Ordered roughly by specificity: more specific / higher-confidence formats
# first, so a line that happens to match both a specific and a generic
# pattern is reported under the specific one (scanner dedupes by span).
SIGNATURES: tuple[Signature, ...] = (
    _sig(
        "aws-access-key-id",
        r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
        "critical",
        "AWS access key ID",
    ),
    _sig(
        "aws-secret-access-key",
        r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "critical",
        "AWS secret access key",
        value_group=1,
    ),
    _sig(
        "gcp-api-key",
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "high",
        "Google Cloud / Maps API key",
    ),
    _sig(
        "github-fine-grained-pat",
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
        "critical",
        "GitHub fine-grained personal access token",
    ),
    _sig(
        "github-token",
        r"\bgh[pousr]_[A-Za-z0-9]{36}\b",
        "critical",
        "GitHub personal/OAuth/app token",
    ),
    _sig(
        "slack-token",
        r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b",
        "high",
        "Slack API token",
    ),
    _sig(
        "slack-webhook",
        r"https://hooks\.slack\.com/services/T[0-9A-Za-z]{6,}/B[0-9A-Za-z]{6,}/[0-9A-Za-z]{16,}",
        "medium",
        "Slack incoming webhook URL",
    ),
    _sig(
        "stripe-live-key",
        r"\b[rs]k_live_[0-9A-Za-z]{16,}\b",
        "critical",
        "Stripe live secret/restricted API key",
    ),
    _sig(
        "twilio-api-key",
        r"\bSK[0-9a-fA-F]{32}\b",
        "high",
        "Twilio API key",
    ),
    _sig(
        "sendgrid-api-key",
        r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
        "high",
        "SendGrid API key",
    ),
    _sig(
        "npm-token",
        r"\bnpm_[A-Za-z0-9]{36}\b",
        "high",
        "npm access token",
    ),
    _sig(
        "private-key-block",
        r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----",
        "critical",
        "Embedded private key material",
    ),
    _sig(
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "medium",
        "JSON Web Token (may embed session/auth material)",
    ),
    _sig(
        "connection-string-with-creds",
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:'\"/@]+:[^\s'\"@]+@",
        "high",
        "Database/queue connection string with embedded credentials",
    ),
    _sig(
        "generic-api-key-assignment",
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
        r"\s*[:=]\s*['\"]([A-Za-z0-9_\-/+=]{16,})['\"]",
        "medium",
        "Generic API key / token / secret assignment",
        value_group=1,
    ),
    _sig(
        "generic-password-assignment",
        r"(?i)\bpassword\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]",
        "medium",
        "Generic hardcoded password assignment",
        value_group=1,
    ),
)


def signature_by_id(sig_id: str) -> Signature | None:
    return next((s for s in SIGNATURES if s.id == sig_id), None)
