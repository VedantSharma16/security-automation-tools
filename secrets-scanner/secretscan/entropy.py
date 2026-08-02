"""Generic high-entropy secret detection.

Vendor-specific regexes (secretscan/rules.py) catch known token formats, but
plenty of real secrets are just "some random-looking string assigned to a
suspiciously named variable" -- internal API keys, service passwords,
one-off tokens. This module flags those by combining two cheap signals:

1. the assignment target's name looks secret-ish (``api_key``, ``token``,
   ``secret``, ``password``, ...), and
2. the assigned value has high Shannon entropy (looks random, not like a
   word, a placeholder, or a short flag value).

Both signals are required -- entropy alone flags too many hashes/UUIDs/build
IDs to be usable, and keyword matching alone flags too many placeholders and
config toggles.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

SUSPICIOUS_KEY_PATTERN = re.compile(
    r"(secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"password|passwd|pwd|auth|credential|client[_-]?secret)",
    re.IGNORECASE,
)

# `name = "value"`, `name: "value"`, `name="value"` (Python/YAML/JSON/.env-ish).
ASSIGNMENT_PATTERN = re.compile(
    r"""['"]?(?P<key>[A-Za-z0-9_.\-]+)['"]?\s*[:=]\s*['"](?P<value>[^'"]{8,200})['"]"""
)

_PLACEHOLDER_PATTERN = re.compile(
    r"^(x{4,}|\*{4,}|\.{3,}|_{4,}|0+|1+|"
    r"changeme|change[_-]?me|your[_-]?.*[_-]?here|example|placeholder|"
    r"todo|fixme|redacted|dummy|fake|sample|test|xxx-xxx-xxx|"
    r"<.*>|\{\{.*\}\}|\$\{.*\})$",
    re.IGNORECASE,
)

DEFAULT_MIN_ENTROPY = 3.5
DEFAULT_MIN_LENGTH = 16


@dataclass(frozen=True)
class EntropyMatch:
    key: str
    value: str
    entropy: float
    start: int
    end: int


def shannon_entropy(s: str) -> float:
    """Shannon entropy of ``s`` in bits per character. Empty string -> 0.0."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def looks_like_placeholder(value: str) -> bool:
    """True for obvious non-secrets: placeholders, template vars, repeated chars."""
    if _PLACEHOLDER_PATTERN.match(value.strip()):
        return True
    # Fewer than 6 distinct characters in a 16+ char string is very unlikely
    # to be a real secret (e.g. "aaaaaaaaaaaaaaaa", "1234567812345678").
    if len(value) >= 16 and len(set(value)) < 6:
        return True
    return False


def find_entropy_secrets(
    line: str,
    min_entropy: float = DEFAULT_MIN_ENTROPY,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> list:
    """Find assignments in ``line`` whose key looks secret-ish and whose value
    is long, high-entropy, and not an obvious placeholder."""
    matches = []
    for m in ASSIGNMENT_PATTERN.finditer(line):
        key, value = m.group("key"), m.group("value")
        if not SUSPICIOUS_KEY_PATTERN.search(key):
            continue
        if len(value) < min_length:
            continue
        if looks_like_placeholder(value):
            continue
        entropy = shannon_entropy(value)
        if entropy < min_entropy:
            continue
        matches.append(EntropyMatch(key=key, value=value, entropy=entropy, start=m.start(), end=m.end()))
    return matches
