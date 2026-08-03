"""Regex-based detection rules for known secret formats.

Each :class:`Rule` matches a *specific, structurally recognizable* secret
format (a cloud provider's API key shape, a private key header, a JWT,
etc.) rather than a generic "looks like a password" heuristic — that lower
bar is handled separately by :mod:`secretscan.entropy`, since name-based
generic detection has a very different (much noisier) precision profile
and needs to be tunable independently.

Rules are plain Python data here rather than an external YAML file: unlike
`process_threat_hunter`'s host-signature rules, secret-format regexes are
effectively fixed (an AWS access key ID has one shape), so there is little
value in runtime-editable rule files for the built-in set. A custom rule
file can still be layered on top via :func:`load_custom_rules`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern
    severity: str
    description: str
    redact: str = "partial"  # "partial" keeps a short prefix, "full" hides everything
    value_group: int = 0  # which capture group holds the actual secret (0 = whole match)
    raw_pattern: str = field(compare=False, default="")

    def extract(self, match: re.Match) -> tuple:
        """Return (span, matched_text) for just the secret value itself.

        Most rules have no capture groups, so the whole match *is* the
        secret. A few (e.g. ``aws-secret-access-key``) also capture the
        surrounding variable name and operator to anchor the match, and
        must report/redact only the value group -- otherwise the "secret"
        field in reports ends up echoing the (unredacted) variable name.
        """
        group = self.value_group or 0
        return match.span(group), match.group(group)


def _rule(
    id: str,
    pattern: str,
    severity: str,
    description: str,
    redact: str = "partial",
    value_group: int = 0,
) -> Rule:
    if severity not in SEVERITY_RANK:
        raise ValueError(f"rule {id!r} has invalid severity {severity!r}; expected one of {SEVERITIES}")
    return Rule(
        id=id,
        pattern=re.compile(pattern),
        severity=severity,
        description=description,
        redact=redact,
        value_group=value_group,
        raw_pattern=pattern,
    )


# Ordered roughly by how confidently the shape alone implies "this is a live
# secret, not a placeholder" -- most specific / lowest false-positive-rate
# patterns first, since the scanner reports the first rule that matches a
# given span of text.
DEFAULT_RULES: tuple = (
    _rule(
        "aws-access-key-id",
        r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
        "critical",
        "AWS access key ID.",
    ),
    _rule(
        "aws-secret-access-key",
        r"(?i)aws_?(secret)?_?(access)?_?key\s*(=|:|:=|=>)\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "critical",
        "AWS secret access key assigned to a variable with an AWS-key-shaped name.",
        value_group=4,
    ),
    _rule(
        "gcp-api-key",
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "high",
        "Google Cloud / Google Maps API key.",
    ),
    _rule(
        "gcp-service-account-key",
        r'"type"\s*:\s*"service_account"',
        "critical",
        "Embedded GCP service account JSON key.",
    ),
    _rule(
        "github-pat",
        r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        "critical",
        "GitHub personal access / OAuth / app / refresh token.",
    ),
    _rule(
        "gitlab-pat",
        r"\bglpat-[A-Za-z0-9_\-]{20}\b",
        "critical",
        "GitLab personal access token.",
    ),
    _rule(
        "slack-token",
        r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b",
        "high",
        "Slack API token.",
    ),
    _rule(
        "slack-webhook",
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}",
        "medium",
        "Slack incoming webhook URL.",
    ),
    _rule(
        "stripe-key",
        r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{20,247}\b",
        "critical",
        "Stripe secret/restricted API key.",
    ),
    _rule(
        "sendgrid-key",
        r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
        "high",
        "SendGrid API key.",
    ),
    _rule(
        "twilio-key",
        r"\bSK[a-z0-9]{32}\b",
        "high",
        "Twilio API key SID.",
    ),
    _rule(
        "npm-token",
        r"\bnpm_[A-Za-z0-9]{36}\b",
        "high",
        "npm access token.",
    ),
    _rule(
        "openai-api-key",
        r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b",
        "critical",
        "OpenAI API key.",
    ),
    _rule(
        "anthropic-api-key",
        r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
        "critical",
        "Anthropic API key.",
    ),
    _rule(
        "private-key-block",
        r"-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----",
        "critical",
        "PEM-encoded private key material (RSA/EC/OpenSSH/PGP/generic).",
        redact="full",
    ),
    _rule(
        "jwt",
        r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "medium",
        "JSON Web Token (may be a live session/auth token).",
    ),
    _rule(
        "basic-auth-url",
        r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'/:@]+:[^\s\"'/:@]+@[^\s\"'/@]+",
        "high",
        "URL with embedded basic-auth credentials (e.g. a database connection string).",
    ),
    _rule(
        "generic-api-key-assignment",
        r"""(?i)\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*(=|:|:=|=>)\s*['"]([A-Za-z0-9_\-/+]{20,})['"]""",
        "medium",
        "Generic API key / access token / client secret assignment.",
        value_group=3,
    ),
    _rule(
        "generic-password-assignment",
        r"""(?i)\b(password|passwd|pwd)\s*(=|:|:=|=>)\s*['"]([^'"\s]{6,})['"]""",
        "medium",
        "Hardcoded password assignment.",
        value_group=3,
    ),
)

RULES_BY_ID = {rule.id: rule for rule in DEFAULT_RULES}


def redact(value: str, mode: str) -> str:
    """Shorten a matched secret so reports never print the full live value."""
    if mode == "full" or len(value) <= 8:
        return "*" * min(len(value), 12)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"
