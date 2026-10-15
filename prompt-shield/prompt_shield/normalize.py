"""Text normalisation so evasion tricks don't defeat the pattern rules."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

# Zero-width and bidi control characters commonly used to hide payloads.
INVISIBLE = {
    "​", "‌", "‍", "⁠", "﻿", "­",
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
}

# Small confusable map (Cyrillic/Greek lookalikes -> Latin).
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "ο": "o", "ι": "i", "ν": "v", "α": "a",
})

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def count_invisible(text: str) -> int:
    return sum(1 for ch in text if ch in INVISIBLE)


def normalize(text: str) -> str:
    """NFKC-fold, drop invisible chars, map homoglyphs, collapse whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if ch not in INVISIBLE)
    text = text.translate(HOMOGLYPHS)
    return re.sub(r"\s+", " ", text).strip()


def decode_base64_blobs(text: str, max_blobs: int = 5) -> list[str]:
    """Return printable-ASCII decodings of base64-looking substrings."""
    out: list[str] = []
    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            dec = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if dec and sum(c.isprintable() or c.isspace() for c in dec) / len(dec) > 0.95:
            out.append(dec)
        if len(out) >= max_blobs:
            break
    return out
