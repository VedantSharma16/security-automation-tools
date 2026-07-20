"""Shannon entropy scoring for generic, unsigned-format secrets.

Signature rules (`rules.py`) catch credentials with a recognizable prefix
(`AKIA...`, `ghp_...`, ...). Plenty of real leaks don't have one — a raw
API key or password assigned to a suspiciously-named variable. Entropy
scoring is the fallback: a random-looking string is a stronger signal of
"secret" than a dictionary word or placeholder, even with no format to
match against.
"""

from __future__ import annotations

import math
from collections import Counter

# Below this many distinct characters, a string is almost certainly not a
# high-entropy secret (e.g. "aaaaaaaaaa" or "0101010101").
_MIN_DISTINCT_CHARS = 6

# Common non-secret values developers actually leave in configs/examples.
# Checked as substrings (case-insensitive) so "your_api_key_here" and
# "CHANGEME_IN_PROD" both get filtered.
PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "changeme",
    "change_me",
    "your_",
    "_here",
    "dummy",
    "sample",
    "redacted",
    "xxxxxxxx",
    "todo",
    "fixme",
    "insert",
    "replace",
    "<",
    ">",
    "{{",
    "}}",
    "${",
)


def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy of `data` in bits per character."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def is_placeholder(value: str) -> bool:
    """Heuristic filter for obvious non-secrets (examples, templates)."""
    lowered = value.lower()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    if len(set(value)) < _MIN_DISTINCT_CHARS:
        return True
    return False


def is_high_entropy_secret(
    value: str, *, min_length: int = 20, min_entropy: float = 3.5
) -> bool:
    """Return True if `value` looks like a random credential.

    Requires both a minimum length and a minimum entropy-per-character so
    short, low-entropy strings (words, short IDs) aren't flagged, and
    filters obvious placeholder text.
    """
    if len(value) < min_length:
        return False
    if is_placeholder(value):
        return False
    return shannon_entropy(value) >= min_entropy
