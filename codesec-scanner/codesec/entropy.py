"""Shannon-entropy helpers used to flag high-entropy strings that look like secrets."""

from __future__ import annotations

import math
import string
from collections import Counter

# Tokens that are high entropy but are almost never secrets in real code.
_COMMON_FALSE_POSITIVES = frozenset(
    {
        "0123456789abcdef",
        "abcdefghijklmnopqrstuvwxyz",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "your-api-key-here",
        "changeme",
        "placeholder",
    }
)

_HEX_DIGITS = frozenset(string.hexdigits)


def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy (bits/char) of a string. Empty string -> 0.0."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def looks_like_secret(token: str, min_length: int = 20, min_entropy: float = 3.5) -> bool:
    """Heuristic: long, high-entropy, mixed-character tokens are likely secrets.

    Pure-hex strings need a higher bar since hashes/commit-ids are common
    and legitimately high entropy without being secret.
    """
    if len(token) < min_length:
        return False
    lowered = token.lower()
    if lowered in _COMMON_FALSE_POSITIVES:
        return False
    if all(c in _HEX_DIGITS for c in token):
        return shannon_entropy(token) >= max(min_entropy, 3.8)
    return shannon_entropy(token) >= min_entropy
