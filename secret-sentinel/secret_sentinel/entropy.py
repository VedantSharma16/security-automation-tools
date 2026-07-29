"""Shannon entropy scoring for generic (non-signature) secret detection.

Named signatures (`patterns.py`) only catch secret formats we already know
about. Custom/internal tokens, hand-rolled API keys, and one-off passwords
don't match any vendor format but are still recognizable because assigned
*secret-like* values tend to be high-entropy random strings, unlike normal
code identifiers or prose. This module scores how "random" a candidate
string looks so the scanner can flag those without a hardcoded pattern.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# Lines shaped like `<name> = "<value>"` / `<name>: "<value>"`, used to pull
# candidate values out of source lines for entropy scoring. The variable
# name itself is checked against `_SECRET_NAME_KEYWORDS` as a substring
# (not a regex \b match) so that common prefixed/suffixed names like
# `db_password`, `stripe_secret_key`, or `AUTH_TOKEN` are all caught —
# a leading `\b(keyword)` anchor would miss all of these because the
# preceding underscore is a word character, so no boundary exists there.
_ASSIGNMENT_RE = re.compile(r"""\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*['"]([^'"\s]{12,})['"]""")

_SECRET_NAME_KEYWORDS = ("key", "secret", "token", "password", "passwd", "pwd", "credential", "auth")

# Obvious placeholders that are high-entropy-looking but never real secrets.
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(x{4,}|0{8,}|1{8,}|change[_-]?me|your[_-].*[_-]here|example|placeholder|"
    r"dummy|fake|test|sample|redacted|<.*>|\$\{.*\})$"
)


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def is_placeholder(value: str) -> bool:
    """True if ``value`` is an obvious placeholder rather than a real secret."""
    return bool(_PLACEHOLDER_RE.match(value.strip()))


def find_candidate_assignments(line: str) -> list[tuple[str, str]]:
    """Return (variable_name, value) pairs for secret-shaped assignments in ``line``.

    A pair is only returned if the variable name contains one of
    ``_SECRET_NAME_KEYWORDS`` as a substring (case-insensitive) — e.g.
    ``db_password``, ``stripe_secret_key``, ``AUTH_TOKEN`` all qualify.
    """
    results = []
    for m in _ASSIGNMENT_RE.finditer(line):
        name, value = m.group(1), m.group(2)
        if any(kw in name.lower() for kw in _SECRET_NAME_KEYWORDS):
            results.append((name, value))
    return results


def is_high_entropy_secret(value: str, threshold: float = 3.5, min_length: int = 12) -> bool:
    """Heuristic: long, high-entropy, non-placeholder values look like real secrets."""
    if len(value) < min_length:
        return False
    if is_placeholder(value):
        return False
    return shannon_entropy(value) >= threshold
