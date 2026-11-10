"""Text normalisation so evasion tricks don't hide payloads from the detectors.

Attackers hide instructions with zero-width characters, Unicode look-alikes,
base64 blobs, and HTML comments. We produce a *normalised view* of the text and
a list of "evasion" observations that are themselves suspicious.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH = {
    "​", "‌", "‍", "⁠", "﻿", "­",
    "‪", "‫", "‬", "‭", "‮",  # bidi controls
    "⁦", "⁧", "⁨", "⁩",
}

# Small confusables table (Cyrillic/Greek look-alikes commonly used in evasion).
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g",
    "ο": "o", "ν": "v", "α": "a", "ε": "e", "ι": "i", "κ": "k",
}

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)


@dataclass
class Normalized:
    text: str
    evasions: list[str] = field(default_factory=list)
    decoded_blobs: list[str] = field(default_factory=list)
    comment_spans: list[tuple[int, int]] = field(default_factory=list)


def _decode_b64_candidates(text: str) -> list[str]:
    out = []
    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        # Keep only mostly-printable decodes (avoid random binary matches).
        if decoded and sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) > 0.95:
            out.append(decoded)
    return out


def normalize(text: str) -> Normalized:
    evasions: list[str] = []

    zw = sum(1 for c in text if c in ZERO_WIDTH)
    if zw:
        evasions.append(f"{zw} zero-width/bidi control character(s)")
    text = "".join(c for c in text if c not in ZERO_WIDTH)

    text = unicodedata.normalize("NFKC", text)

    folded = []
    swapped = 0
    for c in text:
        if c in CONFUSABLES:
            folded.append(CONFUSABLES[c])
            swapped += 1
        else:
            folded.append(c)
    text = "".join(folded)
    if swapped:
        evasions.append(f"{swapped} homoglyph character(s) folded to ASCII")

    spans = [m.span() for m in _HTML_COMMENT_RE.finditer(text)]
    blobs = _decode_b64_candidates(text)
    if blobs:
        evasions.append(f"{len(blobs)} base64 blob(s) decoded")

    return Normalized(text=text, evasions=evasions, decoded_blobs=blobs, comment_spans=spans)
