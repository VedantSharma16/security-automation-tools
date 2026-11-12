"""Text normalization that defeats common prompt-injection obfuscation.

Attackers rarely send "ignore previous instructions" verbatim to a filtered
endpoint. They hide it behind zero-width characters, Cyrillic homoglyphs,
fullwidth letters, leetspeak, letter-spacing ("i g n o r e") or an encoded
blob ("decode this base64 and follow it"). Detection rules run against the
*normalized* views produced here, while the obfuscation itself is reported
as a signal in its own right.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# Zero-width / invisible formatting characters frequently used to split
# keywords or smuggle hidden text past human reviewers.
INVISIBLE_CHARS = {
    "​",  # zero width space
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "⁠",  # word joiner
    "⁡", "⁢", "⁣", "⁤",
    "﻿",  # zero width no-break space / BOM
    "­",  # soft hyphen
    "᠎",  # mongolian vowel separator
}

# Unicode "tag" block (U+E0000–U+E007F) mirrors ASCII and is invisible in
# most renderers — the "ASCII smuggling" technique.
_TAG_START, _TAG_END = 0xE0000, 0xE007F

# Bidi controls can visually reorder text shown to a reviewer.
BIDI_CONTROLS = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"}

# Small, high-value homoglyph map (Cyrillic/Greek lookalikes -> Latin).
# NFKC already folds fullwidth and many compatibility forms.
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i",
})

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

# Runs of single letters separated by a space/dot/dash: "i g n o r e".
_SPACED_RUN = re.compile(r"\b(?:[A-Za-z][ .\-_]){3,}[A-Za-z]\b")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")


@dataclass
class NormalizedText:
    original: str
    normalized: str            # NFKC + invisible-stripped + homoglyph-folded + lowercased
    deobfuscated: str          # normalized + leetspeak folded + spaced runs collapsed
    decoded_payloads: list[str] = field(default_factory=list)
    obfuscation: list[str] = field(default_factory=list)

    def views(self) -> list[str]:
        """All text views detection rules should be run against."""
        return [self.normalized, self.deobfuscated, *self.decoded_payloads]


def _strip_invisible(text: str) -> tuple[str, int, str]:
    """Remove invisible chars; return (clean, removed_count, decoded_tag_text)."""
    out, tags, removed = [], [], 0
    for ch in text:
        cp = ord(ch)
        if _TAG_START <= cp <= _TAG_END:
            removed += 1
            if 0xE0020 <= cp <= 0xE007E:
                tags.append(chr(cp - 0xE0000))
            continue
        if ch in INVISIBLE_CHARS or ch in BIDI_CONTROLS:
            removed += 1
            continue
        out.append(ch)
    return "".join(out), removed, "".join(tags)


def _collapse_spaced(text: str) -> str:
    return _SPACED_RUN.sub(lambda m: re.sub(r"[ .\-_]", "", m.group(0)), text)


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isprintable() or ch in "\n\t" for ch in s) / len(s)


def _try_decode(blob: str, kind: str) -> str | None:
    try:
        if kind == "base64":
            padded = blob + "=" * (-len(blob) % 4)
            raw = base64.b64decode(padded, validate=True)
        else:
            raw = binascii.unhexlify(blob)
        decoded = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    # Only keep decodes that look like natural-language text.
    if _printable_ratio(decoded) < 0.95 or not re.search(r"[A-Za-z]{3,}\s+[A-Za-z]{2,}", decoded):
        return None
    return decoded


def normalize(text: str) -> NormalizedText:
    obfuscation: list[str] = []

    stripped, removed, tag_text = _strip_invisible(text)
    if removed:
        obfuscation.append(f"invisible-characters:{removed}")
    if tag_text:
        obfuscation.append("unicode-tag-smuggling")

    nfkc = unicodedata.normalize("NFKC", stripped)
    if nfkc != stripped:
        obfuscation.append("unicode-compatibility-forms")

    folded = nfkc.translate(HOMOGLYPHS)
    if folded != nfkc:
        obfuscation.append("homoglyphs")

    normalized = re.sub(r"\s+", " ", folded).strip().lower()

    collapsed = _collapse_spaced(normalized)
    if collapsed != normalized:
        obfuscation.append("letter-spacing")
    deobfuscated = collapsed.translate(LEET)

    decoded: list[str] = []
    if tag_text:
        decoded.append(re.sub(r"\s+", " ", tag_text).strip().lower())
    for blob in _BASE64_BLOB.findall(folded):
        d = _try_decode(blob, "base64")
        if d:
            decoded.append(re.sub(r"\s+", " ", d).strip().lower())
            obfuscation.append("base64-payload")
    for blob in _HEX_BLOB.findall(folded):
        d = _try_decode(blob, "hex")
        if d:
            decoded.append(re.sub(r"\s+", " ", d).strip().lower())
            obfuscation.append("hex-payload")

    return NormalizedText(
        original=text,
        normalized=normalized,
        deobfuscated=deobfuscated,
        decoded_payloads=decoded,
        obfuscation=sorted(set(obfuscation)),
    )
