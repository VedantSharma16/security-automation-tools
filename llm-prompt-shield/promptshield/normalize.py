"""Text normalisation to defeat trivial obfuscation before rule matching."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

# zero-width / bidi control characters and the Unicode "tag" block (U+E0000..E007F)
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def count_invisible(text: str) -> int:
    return len(_INVISIBLE.findall(text))


def normalize(text: str) -> str:
    """NFKC-fold (full-width, ligatures), strip invisible chars, collapse whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    return re.sub(r"\s+", " ", text)


def decode_base64_blobs(text: str, max_blobs: int = 8) -> list[str]:
    """Return printable UTF-8 strings decoded from base64-looking substrings."""
    out: list[str] = []
    for m in _B64.finditer(text):
        if len(out) >= max_blobs:
            break
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            s = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if s and sum(c.isprintable() or c.isspace() for c in s) / len(s) > 0.95:
            out.append(s)
    return out
