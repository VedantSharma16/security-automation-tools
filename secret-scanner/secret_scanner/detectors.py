"""Pattern-based and entropy-based secret detectors.

Each `Rule` is a named regex tuned to a specific credential format (cloud
provider keys, VCS tokens, private key blocks, ...). `scan_text` runs every
rule plus a generic high-entropy-assignment fallback over a blob of text and
yields `RawMatch` objects with the byte offsets of each hit, so callers can
map them back to line numbers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from secret_scanner.entropy import find_high_entropy_assignments

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    description: str
    pattern: re.Pattern
    severity: str


@dataclass(frozen=True)
class RawMatch:
    rule_id: str
    description: str
    severity: str
    matched_text: str
    start: int
    end: int


def _rule(rule_id: str, description: str, pattern: str, severity: str, flags: int = 0) -> Rule:
    return Rule(rule_id, description, re.compile(pattern, flags), severity)


RULES: tuple[Rule, ...] = (
    _rule(
        "aws-access-key-id",
        "AWS Access Key ID",
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b",
        SEVERITY_CRITICAL,
    ),
    _rule(
        "aws-secret-access-key",
        "AWS Secret Access Key (assigned to an aws_secret/secret_key-like variable)",
        r"(?i)aws_?(?:secret|access)?_?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        SEVERITY_CRITICAL,
    ),
    _rule(
        "github-pat",
        "GitHub Personal Access Token",
        r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
        SEVERITY_CRITICAL,
    ),
    _rule(
        "github-fine-grained-pat",
        "GitHub fine-grained Personal Access Token",
        r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",
        SEVERITY_CRITICAL,
    ),
    _rule(
        "slack-token",
        "Slack API token",
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        SEVERITY_HIGH,
    ),
    _rule(
        "slack-webhook",
        "Slack incoming webhook URL",
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{5,}/B[A-Za-z0-9_]{5,}/[A-Za-z0-9_]{20,}",
        SEVERITY_HIGH,
    ),
    _rule(
        "google-api-key",
        "Google API key",
        r"\bAIza[A-Za-z0-9_\-]{35}\b",
        SEVERITY_HIGH,
    ),
    _rule(
        "stripe-key",
        "Stripe API key",
        r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
        SEVERITY_CRITICAL,
    ),
    _rule(
        "private-key-block",
        "Private key block (PEM)",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        SEVERITY_CRITICAL,
    ),
    _rule(
        "jwt",
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        SEVERITY_MEDIUM,
    ),
    _rule(
        "generic-connection-string",
        "Credential embedded in a connection string / URL",
        r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s'\"@/]+:[^\s'\"@/]+@[^\s'\"]+",
        SEVERITY_HIGH,
    ),
    _rule(
        "npm-token",
        "npm access token",
        r"\bnpm_[A-Za-z0-9]{36}\b",
        SEVERITY_HIGH,
    ),
)

_GENERIC_ENTROPY_RULE_ID = "generic-high-entropy-assignment"
_GENERIC_ENTROPY_DESCRIPTION = "High-entropy value assigned to a secret-like variable name"


def scan_text(text: str):
    """Yield a RawMatch for every rule hit and every high-entropy assignment in `text`."""
    seen_spans: set[tuple[int, int]] = set()

    for rule in RULES:
        for match in rule.pattern.finditer(text):
            span = match.span()
            if span in seen_spans:
                continue
            seen_spans.add(span)
            yield RawMatch(rule.rule_id, rule.description, rule.severity, match.group(0), *span)

    for _key, value, span, _entropy in find_high_entropy_assignments(text):
        if span in seen_spans:
            continue
        seen_spans.add(span)
        yield RawMatch(
            _GENERIC_ENTROPY_RULE_ID,
            _GENERIC_ENTROPY_DESCRIPTION,
            SEVERITY_MEDIUM,
            value,
            *span,
        )
