"""Regex signatures for well-known credential and secret formats.

Each :class:`SecretPattern` pairs a compiled regex with metadata used for
severity ranking and remediation guidance. These are intentionally narrow
(vendor-specific prefixes/lengths) so they carry high confidence; broader,
noisier detection (arbitrary API keys, passwords) is handled separately by
Shannon-entropy scanning in :mod:`secretscanner.entropy`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class SecretPattern:
    name: str
    category: str
    regex: re.Pattern
    severity: str
    remediation: str


def _p(pattern: str) -> re.Pattern:
    return re.compile(pattern)


PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="AWS Access Key ID",
        category="cloud",
        regex=_p(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        severity="critical",
        remediation="Deactivate the key in IAM immediately and rotate any dependent credentials.",
    ),
    SecretPattern(
        name="AWS Secret Access Key (assignment)",
        category="cloud",
        regex=_p(
            r"(?i)aws_?secret_?(access_)?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"
        ),
        severity="critical",
        remediation="Rotate the key pair in IAM and audit CloudTrail for use of the exposed key.",
    ),
    SecretPattern(
        name="GitHub Personal Access Token",
        category="vcs",
        regex=_p(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        severity="critical",
        remediation="Revoke the token in GitHub Settings > Developer settings and issue a new one.",
    ),
    SecretPattern(
        name="Slack Token",
        category="saas",
        regex=_p(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"),
        severity="high",
        remediation="Revoke the token in the Slack app management console and rotate.",
    ),
    SecretPattern(
        name="Slack Incoming Webhook URL",
        category="saas",
        regex=_p(r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]{20,}"),
        severity="medium",
        remediation="Regenerate the webhook URL in the Slack app configuration.",
    ),
    SecretPattern(
        name="Stripe Secret Key",
        category="payment",
        regex=_p(r"\bsk_(live|test)_[0-9A-Za-z]{16,}\b"),
        severity="critical",
        remediation="Roll the key in the Stripe dashboard; treat 'live' keys as an active incident.",
    ),
    SecretPattern(
        name="Google API Key",
        category="cloud",
        regex=_p(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        severity="high",
        remediation="Restrict or delete the key in Google Cloud Console credentials page.",
    ),
    SecretPattern(
        name="Twilio API Key",
        category="saas",
        regex=_p(r"\bSK[0-9a-fA-F]{32}\b"),
        severity="high",
        remediation="Delete the key in the Twilio console and issue a replacement.",
    ),
    SecretPattern(
        name="NPM Access Token",
        category="vcs",
        regex=_p(r"\bnpm_[A-Za-z0-9]{36}\b"),
        severity="high",
        remediation="Revoke the token with `npm token revoke` and rotate CI secrets.",
    ),
    SecretPattern(
        name="Private Key Block",
        category="crypto",
        regex=_p(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        severity="critical",
        remediation="Treat the key material as fully compromised: revoke/replace it everywhere it is trusted.",
    ),
    SecretPattern(
        name="JSON Web Token",
        category="auth",
        regex=_p(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        severity="medium",
        remediation="Invalidate the session/token if it grants privileged access; short-lived JWTs may be lower risk.",
    ),
    SecretPattern(
        name="Generic Secret Assignment",
        category="generic",
        regex=_p(
            r"(?i)\b(api[_-]?key|secret|token|passwd|password|access[_-]?key)\b"
            r"\s*[:=]\s*['\"][A-Za-z0-9\-_/+=]{16,}['\"]"
        ),
        severity="medium",
        remediation="Confirm whether this is a live credential; if so rotate it and move it to a secrets manager.",
    ),
]


def redact(value: str, keep: int = 4) -> str:
    """Show only a small prefix/suffix of a secret value, e.g. `AKIA****************WXYZ`."""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * (len(value) - keep * 2)}{value[-keep:]}"
