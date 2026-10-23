"""Input normalisation so obfuscated payloads hit the same rules as plain ones."""
import base64
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
# Common Cyrillic/Greek look-alikes folded to ASCII.
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i",
    "ѕ": "s", "ү": "y", "ο": "o", "ι": "i", "α": "a", "ε": "e",
})
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def normalize(text: str) -> str:
    """NFKC-fold, strip zero-width characters, map homoglyphs, lowercase."""
    text = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)
    return text.translate(HOMOGLYPHS).lower()


def had_obfuscation(raw: str) -> list[str]:
    """Return the obfuscation techniques observed in the raw text."""
    found = []
    if any(ord(c) in ZERO_WIDTH for c in raw):
        found.append("zero-width characters")
    if raw != unicodedata.normalize("NFKC", raw).translate(HOMOGLYPHS) and any(
        c in "".join(chr(k) for k in HOMOGLYPHS) for c in raw
    ):
        found.append("homoglyph substitution")
    return found


def decode_base64_segments(text: str) -> list[str]:
    """Decode plausible base64 blobs; keep only printable-text results."""
    out = []
    for m in _B64.finditer(text):
        try:
            dec = base64.b64decode(m.group(0), validate=True).decode("utf-8")
        except Exception:
            continue
        if dec and sum(c.isprintable() or c.isspace() for c in dec) / len(dec) > 0.95:
            out.append(dec)
    return out
