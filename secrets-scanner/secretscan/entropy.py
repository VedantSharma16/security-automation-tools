"""Shannon entropy helpers used to separate real secrets from ordinary text.

A regex alone flags every ``api_key = "..."`` assignment, including ones
whose value is a placeholder like ``"changeme"`` or ``"your-key-here"``.
Requiring the candidate value to also look random (high entropy, no
dictionary-word structure) cuts that noise dramatically without needing an
allowlist for every placeholder string ever written.
"""

from __future__ import annotations

import math
import re
from collections import Counter

_WORDLIKE_RE = re.compile(r"^[a-zA-Z]+$")


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def looks_like_placeholder(value: str) -> bool:
    """Heuristic for common non-secret placeholder values.

    Catches things like ``changeme``, ``your_api_key_here``, ``xxxxxxxx``,
    and ``<redacted>`` that would otherwise pass a naive entropy check.
    """
    lowered = value.lower().strip("<>\"' ")
    if not lowered:
        return True
    if _WORDLIKE_RE.match(lowered) and len(set(lowered)) <= 6:
        # short runs of very few distinct letters, e.g. "xxxxxxxx" or "aaaa"
        return True
    placeholder_markers = (
        "changeme",
        "example",
        "placeholder",
        "your_",
        "your-",
        "<redacted",
        "xxxxxxxx",
        "0000000",
        "1111111",
        "dummy",
        "sample",
        "insert_",
        "todo",
        "fixme",
        "test123",
    )
    return any(marker in lowered for marker in placeholder_markers)


def is_high_entropy(value: str, threshold: float = 4.0, min_length: int = 16) -> bool:
    """True if ``value`` is long and random-looking enough to be a secret."""
    if len(value) < min_length:
        return False
    if looks_like_placeholder(value):
        return False
    return shannon_entropy(value) >= threshold
