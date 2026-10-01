"""Input normalization so evasion tricks don't hide payloads from the rules.

Produces several *views* of a text (original, folded, decoded-payloads);
the scanner runs its rules over all of them and records which view matched.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

# Zero-width and bidi control characters commonly used to split keywords.
_INVISIBLE = dict.fromkeys(
    list(range(0x200B, 0x2010)) + list(range(0x202A, 0x202F)) + list(range(0x2060, 0x2065)) + [0xFEFF, 0x00AD],
)

# Small confusables map (Cyrillic/Greek lookalikes -> ASCII).
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g",
        "ο": "o", "α": "a", "ε": "e", "ι": "i", "ν": "v", "ρ": "p",
    }
)

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def count_invisible(text: str) -> int:
    return sum(1 for ch in text if ord(ch) in _INVISIBLE)


def has_confusables(text: str) -> bool:
    return any(ord(ch) in _CONFUSABLES for ch in text)


def fold(text: str) -> str:
    """NFKC-normalize, drop invisibles, fold lookalikes, collapse whitespace, lowercase."""
    text = unicodedata.normalize("NFKC", text).translate(_INVISIBLE).translate(_CONFUSABLES)
    return re.sub(r"\s+", " ", text).lower()


def decode_payloads(text: str) -> list[tuple[str, str]]:
    """Return (view_name, text) pairs: base64 blobs that decode to readable text, plus ROT13."""
    out: list[tuple[str, str]] = []
    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded and sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) > 0.95:
            out.append(("base64", decoded))
    rot = codecs.decode(text, "rot13")
    out.append(("rot13", rot))
    return out
