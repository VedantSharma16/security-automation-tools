"""Shannon entropy helpers used to flag high-randomness strings that regexes miss."""

from __future__ import annotations

import math
import re
from collections import Counter

_BASE64_ALPHABET = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_HEX_ALPHABET = re.compile(r"^[0-9a-fA-F]+$")

# Candidate secret assignments: `name = value`, `name: "value"`, `name=value;` etc.
_ASSIGNMENT_RE = re.compile(
    r"""
    (?P<key>[A-Za-z0-9_.\-]*
        (?:secret|token|passwd|password|api[_-]?key|access[_-]?key|auth|credential|apikey)
        [A-Za-z0-9_.\-]*)
    \s*[:=]\s*
    ['"]?(?P<value>[A-Za-z0-9+/=_\-.]{12,})['"]?
    """,
    re.IGNORECASE | re.VERBOSE,
)

_PLACEHOLDER_VALUES = {
    "changeme",
    "example",
    "placeholder",
    "your_api_key_here",
    "your-api-key-here",
    "xxxxxxxxxxxxxxxxxxxx",
    "redacted",
    "insert_key_here",
    "todo",
    "n/a",
    "none",
}


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy (bits/char) of a string. Empty string -> 0.0."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def is_placeholder(value: str) -> bool:
    """True if a value looks like an obvious non-secret placeholder."""
    lowered = value.strip().lower()
    if lowered in _PLACEHOLDER_VALUES:
        return True
    if len(set(lowered)) <= 2:  # e.g. "xxxxxxxx" or "00000000"
        return True
    return False


def _max_entropy_for_alphabet(value: str) -> float:
    """Rough theoretical max entropy for the value's likely alphabet, for normalization."""
    if _HEX_ALPHABET.match(value):
        return math.log2(16)
    if _BASE64_ALPHABET.match(value):
        return math.log2(64)
    return math.log2(94)  # printable ASCII, roughly


def find_high_entropy_assignments(text: str, min_entropy_ratio: float = 0.6, min_length: int = 12):
    """Yield (key, value, span, entropy) for `key = value`-style assignments whose
    value has high normalized Shannon entropy and isn't an obvious placeholder.

    min_entropy_ratio is the fraction of the alphabet's theoretical max entropy the
    value's actual entropy must reach, which keeps low-cardinality strings like
    "aaaaaaaaaaaa" or natural-language sentences from tripping the detector.
    """
    for match in _ASSIGNMENT_RE.finditer(text):
        value = match.group("value")
        if len(value) < min_length or is_placeholder(value):
            continue
        entropy = shannon_entropy(value)
        ratio = entropy / _max_entropy_for_alphabet(value)
        if ratio >= min_entropy_ratio:
            yield match.group("key"), value, match.span("value"), entropy
