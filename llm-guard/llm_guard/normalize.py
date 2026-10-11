"""Input normalization and de-obfuscation.

Attackers hide injections behind zero-width characters, homoglyphs, leetspeak,
base64 or ROT13. We scan the raw text *and* every decoded view of it.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­‪‫‬‭‮"))
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def normalize(text: str) -> str:
    """NFKC-fold, strip invisible/bidi characters, collapse whitespace, lowercase."""
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return re.sub(r"\s+", " ", text).strip().lower()


def has_hidden_chars(text: str) -> bool:
    return any(ord(c) in _ZERO_WIDTH for c in text)


def decode_base64_candidates(text: str) -> list[str]:
    out = []
    for m in _B64_RE.finditer(text):
        try:
            raw = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded.isprintable() or "\n" in decoded:
            out.append(decoded)
    return out


def views(text: str) -> list[tuple[str, str]]:
    """Return (view_name, normalized_text) pairs to scan."""
    base = normalize(text)
    result = [("raw", base)]
    leet = base.translate(_LEET)
    if leet != base:
        result.append(("leetspeak", leet))
    rot = codecs.decode(base, "rot_13")
    result.append(("rot13", rot))
    for dec in decode_base64_candidates(text):
        result.append(("base64", normalize(dec)))
    return result
