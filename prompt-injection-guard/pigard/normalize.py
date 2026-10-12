"""Input normalisation so obfuscated payloads hit the same rules as plain ones.

Attackers hide instructions with zero-width characters, homoglyphs, and
base64. We return every plausible *view* of the text for the rules to inspect.
"""
from __future__ import annotations

import base64
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
# Small confusables map (Cyrillic/Greek lookalikes -> Latin).
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "ο": "o", "α": "a", "ε": "e", "ι": "i",
})
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def has_hidden_chars(text: str) -> bool:
    return any(ord(c) in ZERO_WIDTH for c in text)


def has_homoglyphs(text: str) -> bool:
    return any(c in "".join(chr(k) for k in HOMOGLYPHS) for c in text)


def canonical(text: str) -> str:
    """NFKC-normalise, strip invisible characters, fold homoglyphs, collapse whitespace."""
    t = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH).translate(HOMOGLYPHS)
    return re.sub(r"\s+", " ", t).strip()


def decoded_base64(text: str) -> list[str]:
    """Return printable UTF-8 payloads decoded from base64-looking substrings."""
    out = []
    for m in _B64.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if raw and sum(c.isprintable() or c.isspace() for c in raw) / len(raw) > 0.95:
            out.append(raw)
    return out


def views(text: str) -> list[tuple[str, str]]:
    """(label, text) pairs: the canonical text plus any decoded hidden layers."""
    base = canonical(text)
    result = [("plain", base)]
    for dec in decoded_base64(text):
        result.append(("base64", canonical(dec)))
    return result
