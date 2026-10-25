"""Input normalization to defeat common obfuscation before rules run.

Attackers hide payloads with zero-width characters, Unicode look-alikes
(Cyrillic 'о' for Latin 'o'), fullwidth forms, and base64 wrapping. Rules are
run against every view this module produces.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

# Zero-width and bidi-control characters used to split keywords invisibly.
_INVISIBLE = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD,
     0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]
)

# Small confusables table: Cyrillic/Greek letters that render like Latin ones.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ɡ": "g",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "ν": "v", "ρ": "p",
})

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_WS_RE = re.compile(r"\s+")


def strip_invisible(text: str) -> str:
    return text.translate(_INVISIBLE)


def normalize(text: str) -> str:
    """NFKC-fold, drop invisible characters, fold confusables, collapse spaces."""
    text = unicodedata.normalize("NFKC", strip_invisible(text))
    text = text.translate(_CONFUSABLES)
    return _WS_RE.sub(" ", text).strip()


def had_obfuscation(raw: str) -> bool:
    """True if the raw text contains invisible characters or mixed-script words."""
    if any(ord(c) in _INVISIBLE for c in raw):
        return True
    for word in re.findall(r"\w+", raw):
        if len(word) > 2 and any(c.isascii() and c.isalpha() for c in word) and any(
            c.translate(_CONFUSABLES) != c for c in word
        ):
            return True
    return False


def decode_base64_blobs(text: str, max_blobs: int = 5) -> list[str]:
    """Decode plausible base64 substrings that yield printable UTF-8 text."""
    out: list[str] = []
    for match in _B64_RE.findall(text)[:max_blobs]:
        padded = match + "=" * (-len(match) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded and sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) > 0.95:
            out.append(decoded)
    return out
