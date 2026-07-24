"""Detection rules: known-format secret patterns plus a generic
high-entropy fallback for anything that doesn't match a named provider.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass(frozen=True)
class Rule:
    rule_id: str
    description: str
    severity: str
    pattern: re.Pattern
    group: int = 0  # regex group holding the secret value to redact/fingerprint


# Known-format rules: high precision, matched against a specific vendor
# token shape. Ordered roughly by how distinctive the pattern is, so a
# line only ever needs to be checked against the generic rule if nothing
# more specific matched.
RULES: list[Rule] = [
    Rule(
        "aws-access-key-id",
        "AWS Access Key ID",
        "HIGH",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    Rule(
        "aws-secret-access-key",
        "AWS Secret Access Key",
        "CRITICAL",
        re.compile(
            r"(?i)aws_secret(_access)?_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        group=2,
    ),
    Rule(
        "github-token",
        "GitHub Personal / App Access Token",
        "HIGH",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    ),
    Rule(
        "github-fine-grained-pat",
        "GitHub Fine-Grained Personal Access Token",
        "HIGH",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
    ),
    Rule(
        "slack-token",
        "Slack Token",
        "HIGH",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"),
    ),
    Rule(
        "slack-webhook",
        "Slack Incoming Webhook URL",
        "MEDIUM",
        re.compile(
            r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]{6,12}/B[0-9A-Za-z_]{6,12}/[0-9A-Za-z_]{20,24}"
        ),
    ),
    Rule(
        "google-api-key",
        "Google API Key",
        "MEDIUM",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ),
    Rule(
        "stripe-live-key",
        "Stripe Live Secret/Restricted Key",
        "CRITICAL",
        re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,247}\b"),
    ),
    Rule(
        "twilio-api-key",
        "Twilio API Key",
        "HIGH",
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    ),
    Rule(
        "private-key-block",
        "Private Key Block (PEM)",
        "CRITICAL",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        "MEDIUM",
        re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
]

# Variable-name/keyword hints used by the generic high-entropy detector.
_GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|secret|token|password|passwd|pwd|"
    r"access[_-]?key|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*"
    r"['\"]([A-Za-z0-9+/=_\-]{12,100})['\"]"
)

# Common placeholder / example values that would otherwise trip the
# generic detector. Kept intentionally broad — false positives here are
# far more costly to a user's trust in the tool than a missed toy example.
_PLACEHOLDER = re.compile(
    r"(?i)(changeme|change[_-]?me|your[_-]?(api|secret|token)|example|"
    r"placeholder|xxxxx|<.*>|\{\{.*\}\}|dummy|fake|sample|redacted|todo|"
    r"insert[_-]?key|replace[_-]?me|test[_-]?(key|token|secret)?$)"
)


def shannon_entropy(data: str) -> float:
    """Average bits of entropy per character (Shannon entropy)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def find_generic_secrets(line: str, min_entropy: float = 3.5):
    """Yield (matched_value, span) for keyword-adjacent high-entropy strings.

    This is a heuristic fallback for secrets that don't match a known
    vendor format: `<keyword> = "<random-looking value>"`. It is
    deliberately conservative (placeholder denylist + entropy floor) to
    keep noise manageable, but it will never be as precise as a
    format-specific rule above.
    """
    for match in _GENERIC_ASSIGNMENT.finditer(line):
        value = match.group(2)
        if _PLACEHOLDER.search(value):
            continue
        if not (any(c.isalpha() for c in value) and any(c.isdigit() for c in value)):
            # require alnum mix - cuts out plain English placeholder words
            continue
        if shannon_entropy(value) < min_entropy:
            continue
        yield value, match.span(2)
