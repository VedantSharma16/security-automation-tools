"""Text normalisation to defeat trivial obfuscation before rules run."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

# Zero-width / bidi control characters commonly used to hide payloads.
INVISIBLE = {
    "​", "‌", "‍", "⁠", "﻿",
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
}

# Common leetspeak / homoglyph substitutions (Cyrillic look-alikes -> Latin).
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j",
})
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")


def count_invisible(text: str) -> int:
    return sum(1 for ch in text if ch in INVISIBLE)


def strip_invisible(text: str) -> str:
    return "".join(ch for ch in text if ch not in INVISIBLE)


def normalize(text: str) -> str:
    """NFKC-fold, drop invisible chars, map homoglyphs, lowercase, squash whitespace."""
    text = unicodedata.normalize("NFKC", strip_invisible(text))
    text = text.translate(HOMOGLYPHS).lower()
    return re.sub(r"\s+", " ", text).strip()


def deleet(text: str) -> str:
    return text.translate(LEET)


def decode_base64_chunks(text: str, max_chunks: int = 10) -> list[str]:
    """Return printable-text decodings of base64-looking substrings."""
    out: list[str] = []
    for m in _B64_RE.finditer(text):
        if len(out) >= max_chunks:
            break
        chunk = m.group(0)
        try:
            raw = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded and sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) > 0.95:
            out.append(decoded)
    return out
