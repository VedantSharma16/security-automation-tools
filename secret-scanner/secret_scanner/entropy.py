"""Shannon-entropy based detection for secrets with no known format.

Signature matching in `signatures.py` only catches formats it knows about.
This module scans for long, high-entropy tokens (the kind of random-looking
base64/hex blob a generic API key or session secret tends to be) as a
lower-precision fallback, so the scanner still flags "some kind of secret is
probably here" even for an unrecognized provider.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

# Candidate tokens: runs of base64-ish or hex-ish characters, long enough
# that a false positive from ordinary prose/code identifiers is unlikely.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_=\-]{20,}")

_HEX_CHARS = set("0123456789abcdefABCDEF")  # secret-scanner:ignore
_BASE64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="  # secret-scanner:ignore
)


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character, using the string's own symbol frequencies."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@dataclass(frozen=True)
class EntropyConfig:
    min_length: int = 20
    hex_threshold: float = 3.0
    base64_threshold: float = 4.3


def _looks_like_hex(token: str) -> bool:
    return len(token) >= 20 and all(c in _HEX_CHARS for c in token)


def _looks_like_base64(token: str) -> bool:
    return all(c in _BASE64_CHARS for c in token)


def _is_low_variety(token: str) -> bool:
    """Reject tokens that are entropy-high only because they're long, not
    because they're actually random (e.g. 'abababababababababab...')."""
    return len(set(token.lower())) <= 4


def find_high_entropy_tokens(line: str, config: EntropyConfig | None = None):
    """Yield (token, start, end, entropy) for high-entropy substrings of `line`."""
    config = config or EntropyConfig()
    for m in _TOKEN_RE.finditer(line):
        token = m.group(0)
        if len(token) < config.min_length or _is_low_variety(token):
            continue

        if _looks_like_hex(token):
            entropy = shannon_entropy(token.lower())
            if entropy >= config.hex_threshold:
                yield token, m.start(), m.end(), entropy
                continue

        if _looks_like_base64(token):
            entropy = shannon_entropy(token)
            if entropy >= config.base64_threshold:
                yield token, m.start(), m.end(), entropy
