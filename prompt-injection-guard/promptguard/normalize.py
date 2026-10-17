"""Text normalisation that defeats common obfuscation before rules run."""

from __future__ import annotations

import base64
import re
import unicodedata

# Zero-width / bidi control characters commonly used to hide or split payloads.
_INVISIBLE = {
    "​", "‌", "‍", "⁠", "﻿", "­",
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
}
# Cyrillic/Greek lookalikes mapped to Latin.
_LOOKALIKES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "ο": "o", "ν": "v", "ρ": "p",
}
_HOMOGLYPHS = str.maketrans({**_LOOKALIKES, **{k.upper(): v.upper() for k, v in _LOOKALIKES.items()}})
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def count_invisible(text: str) -> int:
    """Count invisible control chars, including the Unicode 'tag' block (U+E0000+)."""
    return sum(1 for c in text if c in _INVISIBLE or 0xE0000 <= ord(c) <= 0xE007F)


def decode_tag_chars(text: str) -> str:
    """Recover ASCII smuggled via Unicode tag characters (ASCII Smuggling)."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if c not in _INVISIBLE and not 0xE0000 <= ord(c) <= 0xE007F)
    text = text.translate(_HOMOGLYPHS)
    return re.sub(r"[ \t ]+", " ", text)


def decode_base64_blobs(text: str) -> list[str]:
    """Return printable-text payloads hidden in base64 blobs."""
    out = []
    for m in _B64.finditer(text):
        try:
            raw = base64.b64decode(m.group(0), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if raw and sum(c.isprintable() or c.isspace() for c in raw) / len(raw) > 0.95:
            out.append(raw)
    return out
