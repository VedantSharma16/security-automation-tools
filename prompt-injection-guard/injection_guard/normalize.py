"""Text canonicalisation that undoes common prompt-injection obfuscation.

Attackers rarely send ``ignore previous instructions`` in plain ASCII when a
filter is in the way. This module reverses the cheap tricks *before* any
detection rule runs, and records each trick it had to undo as a **signal**
(using an obfuscation technique is itself suspicious, regardless of content):

* Unicode *tag characters* (U+E0000-U+E007F) - "ASCII smuggling": invisible to
  a human reviewer but still read by the model. Decoded back to ASCII.
* Zero-width characters used to split keywords (``ig​nore``).
* Bidirectional control characters (Trojan-Source style display tricks).
* Fullwidth / compatibility forms (``ｉｇｎｏｒｅ``) via NFKC.
* Cyrillic/Greek homoglyphs mixed into Latin words (``іgnоre``).
* Base64 blobs - decoded and returned separately so the detector can scan
  the hidden payload too.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "­"}
BIDI_CONTROLS = {chr(c) for c in range(0x202A, 0x202F)} | {chr(c) for c in range(0x2066, 0x206A)}
TAG_RANGE = range(0xE0000, 0xE0080)

# Confusable characters that render (near-)identically to Latin letters.
HOMOGLYPHS = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k",
    "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
}

_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_WORD = re.compile(r"\w+", re.UNICODE)


@dataclass
class Normalized:
    """Result of canonicalising a piece of text."""

    original: str
    text: str
    signals: list[str] = field(default_factory=list)
    decoded_segments: list[str] = field(default_factory=list)

    @property
    def all_text(self) -> str:
        """Canonical text plus any decoded hidden payloads, for rule matching."""
        return "\n".join([self.text, *self.decoded_segments])


def _decode_tag_chars(text: str) -> tuple[str, bool]:
    found = False
    out = []
    for ch in text:
        cp = ord(ch)
        if cp in TAG_RANGE:
            found = True
            inner = cp - 0xE0000
            # U+E0020..U+E007E mirror printable ASCII; the rest are framing chars.
            if 0x20 <= inner <= 0x7E:
                out.append(chr(inner))
        else:
            out.append(ch)
    return "".join(out), found


def _fold_homoglyphs(text: str) -> tuple[str, bool]:
    """Replace confusables, flagging only *mixed-script* words.

    A word written entirely in Cyrillic is ordinary Russian text and must not
    be flagged; a Latin word with one Cyrillic ``о`` slipped in is an attack.
    """
    mixed = False
    for match in _WORD.finditer(text):
        word = match.group()
        has_latin = any("a" <= c.lower() <= "z" for c in word)
        has_confusable = any(c in HOMOGLYPHS for c in word)
        if has_latin and has_confusable:
            mixed = True
            break
    if not mixed:
        return text, False
    return "".join(HOMOGLYPHS.get(c, c) for c in text), True


def _decode_base64_blobs(text: str) -> list[str]:
    decoded = []
    for token in _BASE64_TOKEN.findall(text):
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(c.isprintable() or c.isspace() for c in candidate)
        letters = sum(c.isalpha() for c in candidate)
        # Require mostly-printable output with real words, so random IDs,
        # hashes and API tokens that happen to decode are ignored.
        if candidate and printable / len(candidate) > 0.95 and letters / len(candidate) > 0.5 and " " in candidate:
            decoded.append(candidate)
    return decoded


def normalize(text: str) -> Normalized:
    """Canonicalise ``text`` and report which obfuscation techniques were found."""
    signals: list[str] = []

    work, had_tags = _decode_tag_chars(text)
    if had_tags:
        signals.append("unicode_tag_smuggling")

    if any(c in ZERO_WIDTH for c in work):
        signals.append("zero_width_chars")
        work = "".join(c for c in work if c not in ZERO_WIDTH)

    if any(c in BIDI_CONTROLS for c in work):
        signals.append("bidi_control_chars")
        work = "".join(c for c in work if c not in BIDI_CONTROLS)

    nfkc = unicodedata.normalize("NFKC", work)
    if nfkc != work and any(0xFF01 <= ord(c) <= 0xFF5E for c in work):
        signals.append("fullwidth_forms")
    work = nfkc

    work, had_homoglyphs = _fold_homoglyphs(work)
    if had_homoglyphs:
        signals.append("homoglyph_mixing")

    decoded = _decode_base64_blobs(work)
    if decoded:
        signals.append("base64_payload")

    return Normalized(original=text, text=work, signals=signals, decoded_segments=decoded)
