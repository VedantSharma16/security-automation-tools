"""Shannon-entropy based detection of high-randomness tokens.

Vendor-specific regexes in :mod:`secretscanner.patterns` only catch known
formats. Generic API keys, passwords, and one-off tokens have no fixed
shape, so we fall back to flagging tokens that *look* random: long strings
drawn from a hex or base64-like alphabet whose per-character entropy is
above a threshold tuned for that alphabet.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

HEX_CHARS = set("0123456789abcdefABCDEF")
BASE64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)

# Thresholds are bits-per-character. Hex has a max possible entropy of 4.0
# bits/char (16 symbols); base64 tops out around 6.0 (64 symbols). Real
# secrets tend to sit close to the ceiling for their alphabet; low-entropy
# "random-looking" strings (repeated chars, words, hex-encoded English) sit
# well below it.
HEX_ENTROPY_THRESHOLD = 3.0
BASE64_ENTROPY_THRESHOLD = 4.3

MIN_TOKEN_LENGTH = 20
MAX_TOKEN_LENGTH = 128

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{%d,%d}" % (MIN_TOKEN_LENGTH, MAX_TOKEN_LENGTH))


def shannon_entropy(data: str) -> float:
    """Bits of entropy per character, based on observed symbol frequencies."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


@dataclass(frozen=True)
class EntropyMatch:
    token: str
    entropy: float
    alphabet: str  # "hex" or "base64"


def _classify_alphabet(token: str) -> str | None:
    chars = set(token)
    if chars <= HEX_CHARS:
        return "hex"
    if chars <= BASE64_CHARS:
        return "base64"
    return None


def find_high_entropy_tokens(line: str) -> list[EntropyMatch]:
    """Scan a line for standalone tokens whose entropy exceeds the threshold
    for their apparent alphabet. Skips tokens that are all one repeated
    character or a small alphabet (e.g. "aaaaaaaaaaaaaaaaaaaa") outright.
    """
    matches: list[EntropyMatch] = []
    for token in _TOKEN_RE.findall(line):
        if len(set(token)) < 6:
            continue
        alphabet = _classify_alphabet(token)
        if alphabet is None:
            continue
        entropy = shannon_entropy(token)
        threshold = HEX_ENTROPY_THRESHOLD if alphabet == "hex" else BASE64_ENTROPY_THRESHOLD
        if entropy >= threshold:
            matches.append(EntropyMatch(token=token, entropy=entropy, alphabet=alphabet))
    return matches
