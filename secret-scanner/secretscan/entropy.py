"""Shannon-entropy heuristic for secrets that don't match a known format.

Regex rules in :mod:`secretscan.rules` only catch secret shapes we already
know (an AWS key, a GitHub PAT, ...). Plenty of real leaks are a random
value assigned to a suspiciously-named variable in a language/company's own
internal format -- ``internal_service_token = "9f8e7d..."`` -- that no
public rule set will ever enumerate. For those, this module flags
assignments to security-sounding names whose value looks close to random,
using Shannon entropy as a cheap proxy for "not a word, not a placeholder".

This is a blunter instrument than the regex rules and produces more false
positives (UUIDs, hashes of public data, minified build IDs); it is a
separate, lower-confidence signal by design, and callers should keep it
opt-in-suppressible via the allowlist.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

SUSPICIOUS_NAME = re.compile(
    r"(?i)(^|[_-])(secret|token|api[_-]?key|apikey|access[_-]?key|auth|credential|"
    r"passwd|password|pwd|private[_-]?key|client[_-]?secret|session[_-]?id)($|[_-])"
)

# name (= or : or =>) 'value'  -- the value itself is captured separately so
# we can measure its entropy independent of the surrounding quoting style.
_ASSIGNMENT = re.compile(
    r"""(?i)([a-z_][a-z0-9_]*)\s*(?:=|:|:=|=>)\s*['"]([A-Za-z0-9+/_\-\.]{16,})['"]"""
)

# Values that are almost certainly placeholders regardless of entropy.
_PLACEHOLDER = re.compile(
    r"(?i)^(changeme|change[_-]?me|your[_-]?\w+|placeholder|example|xxx+|"
    r"test|dummy|fake|sample|redacted|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\})$"
)

MIN_LENGTH = 20
MIN_ENTROPY_BITS_PER_CHAR = 3.3
MIN_CHAR_CLASSES = 2

_CHAR_CLASS_PATTERNS = (
    re.compile(r"[a-z]"),
    re.compile(r"[A-Z]"),
    re.compile(r"[0-9]"),
    re.compile(r"[^a-zA-Z0-9]"),
)


def char_class_count(value: str) -> int:
    """Count how many of {lowercase, uppercase, digit, symbol} appear in ``value``.

    Plain natural-language words/phrases ("correcthorsebatterystaple") can
    score surprisingly high on raw Shannon entropy while using only one
    character class; real generated secrets (base64/hex tokens, passwords)
    almost always mix at least two. This cuts a large class of false
    positives that entropy alone lets through.
    """
    return sum(1 for pattern in _CHAR_CLASS_PATTERNS if pattern.search(value))


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits per character."""
    if not value:
        return 0.0
    counts: dict = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


@dataclass(frozen=True)
class EntropyCandidate:
    variable_name: str
    value: str
    entropy: float


def find_high_entropy_assignments(
    line: str,
    min_length: int = MIN_LENGTH,
    min_entropy: float = MIN_ENTROPY_BITS_PER_CHAR,
) -> list:
    """Find assignments in ``line`` to a security-sounding name whose value
    is long and high-entropy enough to plausibly be a live secret."""
    candidates = []
    for match in _ASSIGNMENT.finditer(line):
        name, value = match.group(1), match.group(2)
        if not SUSPICIOUS_NAME.search(name):
            continue
        if len(value) < min_length:
            continue
        if _PLACEHOLDER.match(value):
            continue
        if char_class_count(value) < MIN_CHAR_CLASSES:
            continue
        entropy = shannon_entropy(value)
        if entropy >= min_entropy:
            candidates.append(EntropyCandidate(variable_name=name, value=value, entropy=entropy))
    return candidates
