"""Text normalization that defeats common obfuscation before rules run.

Attackers hide injections with zero-width characters, Unicode homoglyphs,
leetspeak-ish spacing, and base64 wrapping. We normalize first so the rule set
can stay small and readable, and report *that* obfuscation occurred.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# Zero-width, bidi-control and other invisible formatting characters.
INVISIBLE = {
    "​", "‌", "‍", "⁠", "﻿", "­",
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
}

# Small confusable map (Cyrillic/Greek lookalikes -> Latin).
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g",
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "ι": "i", "τ": "t",
}

_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass
class Normalized:
    text: str
    invisible_chars: int = 0
    homoglyphs: int = 0
    decoded_blobs: list[str] = field(default_factory=list)

    @property
    def obfuscated(self) -> bool:
        return bool(self.invisible_chars or self.homoglyphs or self.decoded_blobs)


def _decode_b64_blobs(text: str) -> list[str]:
    out = []
    for m in _B64.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            s = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        # Only keep decodes that look like natural-language text.
        if s and sum(c.isprintable() or c.isspace() for c in s) / len(s) > 0.95 and " " in s:
            out.append(s)
    return out


def normalize(text: str) -> Normalized:
    invisible = sum(1 for c in text if c in INVISIBLE)
    stripped = "".join(c for c in text if c not in INVISIBLE)
    folded = unicodedata.normalize("NFKC", stripped)
    homo = sum(1 for c in folded if c in HOMOGLYPHS)
    folded = "".join(HOMOGLYPHS.get(c, c) for c in folded)
    blobs = _decode_b64_blobs(folded)
    folded = re.sub(r"\s+", " ", folded).strip()
    return Normalized(folded, invisible, homo, blobs)
