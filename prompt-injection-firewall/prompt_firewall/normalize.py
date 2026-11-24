"""Text normalisation and obfuscation detection.

Attackers rarely send ``ignore previous instructions`` in plain ASCII any
more. This module undoes the common evasion layers *before* the rule engine
runs, and reports each layer it had to peel off as evidence in its own right:

* zero-width / invisible characters splitting keywords (``ig​nore``)
* Unicode "tag" characters (U+E0000 block) - invisible "ASCII smuggling"
  payloads that many tokenizers still read
* bidirectional override characters (Trojan-Source style reordering)
* Cyrillic/Greek homoglyphs mixed into Latin words (``іgnоrе``)
* NFKC compatibility forms (full-width ``ｉｇｎｏｒｅ``, ligatures, etc.)
* base64-encoded blobs that decode to readable text
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH = {
    "​",  # zero width space
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "⁠",  # word joiner
    "⁡", "⁢", "⁣", "⁤",  # invisible math operators
    "﻿",  # zero width no-break space / BOM
    "­",  # soft hyphen
    "᠎",  # mongolian vowel separator
}

BIDI_CONTROLS = {
    "‪", "‫", "‬", "‭", "‮",  # embeddings / overrides
    "⁦", "⁧", "⁨", "⁩",  # isolates
    "‎", "‏",  # LRM / RLM
}

TAG_START, TAG_END = 0xE0000, 0xE007F

# Visually-confusable Cyrillic / Greek letters -> Latin. Deliberately small:
# only letters that are near-identical in common fonts.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    "α": "a", "ο": "o", "ε": "e", "ι": "i", "ν": "v", "κ": "k", "ρ": "p",
    "τ": "t", "υ": "u", "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
}

BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
WORD_RE = re.compile(r"\w{3,}", re.UNICODE)


@dataclass
class NormalizationResult:
    original: str
    normalized: str
    zero_width_count: int = 0
    bidi_count: int = 0
    tag_payload: str = ""
    mixed_script_words: list[str] = field(default_factory=list)
    decoded_blobs: list[str] = field(default_factory=list)

    @property
    def was_obfuscated(self) -> bool:
        return bool(
            self.zero_width_count
            or self.bidi_count
            or self.tag_payload
            or self.mixed_script_words
        )


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script):
            return script
    return "OTHER"


def find_mixed_script_words(text: str) -> list[str]:
    """Words that mix Latin with Cyrillic/Greek letters - a homoglyph tell.

    Whole words in Cyrillic or Greek are legitimate (other languages); it is
    the *mix inside one word* that is almost never benign.
    """
    hits = []
    for match in WORD_RE.finditer(text):
        scripts = {_script_of(c) for c in match.group()} - {None}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            hits.append(match.group())
    return hits


def extract_tag_payload(text: str) -> str:
    """Decode Unicode tag characters (U+E0020-U+E007E map to ASCII)."""
    return "".join(
        chr(ord(c) - TAG_START) for c in text if TAG_START + 0x20 <= ord(c) <= TAG_START + 0x7E
    )


def decode_base64_blobs(text: str, min_len: int = 12) -> list[str]:
    """Return base64 blobs in ``text`` that decode to mostly-printable text."""
    decoded = []
    for match in BASE64_RE.finditer(text):
        blob = match.group()
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if len(candidate) < min_len:
            continue
        printable = sum(1 for c in candidate if c.isprintable() or c in "\n\t")
        if printable / len(candidate) >= 0.9:
            decoded.append(candidate)
    return decoded


def normalize(text: str) -> NormalizationResult:
    """Strip evasion layers and return canonical text plus what was removed."""
    result = NormalizationResult(original=text, normalized=text)

    result.tag_payload = extract_tag_payload(text)
    result.zero_width_count = sum(1 for c in text if c in ZERO_WIDTH)
    result.bidi_count = sum(1 for c in text if c in BIDI_CONTROLS)
    result.mixed_script_words = find_mixed_script_words(text)

    cleaned = "".join(
        c
        for c in text
        if c not in ZERO_WIDTH and c not in BIDI_CONTROLS and not TAG_START <= ord(c) <= TAG_END
    )
    cleaned = unicodedata.normalize("NFKC", cleaned)
    cleaned = "".join(HOMOGLYPHS.get(c, c) for c in cleaned)

    result.normalized = cleaned
    result.decoded_blobs = decode_base64_blobs(cleaned)
    return result


def strip_invisible(text: str) -> str:
    """Remove zero-width, bidi-control and tag characters (used by sanitize)."""
    return "".join(
        c
        for c in text
        if c not in ZERO_WIDTH and c not in BIDI_CONTROLS and not TAG_START <= ord(c) <= TAG_END
    )
