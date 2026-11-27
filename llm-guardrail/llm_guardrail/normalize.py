"""Text normalization that undoes common prompt-injection evasion tricks.

Attackers rarely write "ignore previous instructions" in plain ASCII once a
filter exists. They use fullwidth/compatibility characters, zero-width
joiners between letters, Cyrillic look-alikes, leetspeak, and base64. The
detectors in this package always run against the *normalized* view of the
text, and the normalizer also reports which tricks it saw — because the
presence of an evasion technique is itself a signal.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# Invisible / formatting code points commonly used to split keywords or hide text.
ZERO_WIDTH = {
    "​",  # zero width space
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "⁠",  # word joiner
    "⁡", "⁢", "⁣", "⁤",
    "﻿",  # zero width no-break space / BOM
    "­",  # soft hyphen
    "᠎",  # mongolian vowel separator
}
# Unicode "tag" characters (U+E0000-U+E007F) can smuggle an entire invisible
# ASCII payload ("ASCII smuggling"). Each maps to ASCII by subtracting 0xE0000.
TAG_RANGE = range(0xE0000, 0xE0080)
# Bidi controls can visually reorder text so a human reviewer sees something
# different from what the model receives.
BIDI_CONTROLS = {chr(c) for c in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)}

# Small confusables map: Cyrillic / Greek letters that render like Latin ones.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
    "α": "a", "ο": "o", "ν": "v", "ι": "i", "Ι": "I", "Ο": "O", "Α": "A",
}

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

# Base64 blobs long enough to carry a sentence. Shorter runs are ignored to
# avoid decoding ordinary identifiers.
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass
class NormalizedText:
    original: str
    text: str  # normalized, lower-cased, evasion-stripped
    evasions: list[str] = field(default_factory=list)
    decoded_payloads: list[str] = field(default_factory=list)
    hidden_payload: str = ""  # text recovered from Unicode tag characters

    @property
    def searchable(self) -> str:
        """All text a detector should look at: normalized body plus anything
        recovered from encodings or invisible characters."""
        extras = [p for p in (*self.decoded_payloads, self.hidden_payload) if p]
        return "\n".join([self.text, *extras])


def _decode_b64_candidates(text: str) -> list[str]:
    decoded: list[str] = []
    for match in B64_RE.finditer(text):
        blob = match.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            candidate = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in candidate)
        # Require mostly printable text with some spaces — i.e. a sentence,
        # not a random hash that happened to decode.
        if candidate and printable / len(candidate) > 0.95 and " " in candidate:
            decoded.append(candidate.lower())
    return decoded


def normalize(text: str) -> NormalizedText:
    evasions: list[str] = []

    hidden = "".join(chr(ord(ch) - 0xE0000) for ch in text if ord(ch) in TAG_RANGE)
    if hidden:
        evasions.append("unicode_tag_smuggling")
    working = "".join(ch for ch in text if ord(ch) not in TAG_RANGE)

    if any(ch in ZERO_WIDTH for ch in working):
        evasions.append("zero_width_chars")
        working = "".join(ch for ch in working if ch not in ZERO_WIDTH)

    if any(ch in BIDI_CONTROLS for ch in working):
        evasions.append("bidi_override")
        working = "".join(ch for ch in working if ch not in BIDI_CONTROLS)

    nfkc = unicodedata.normalize("NFKC", working)
    if nfkc != working:
        evasions.append("compatibility_chars")
    working = nfkc

    # Only count homoglyphs when they sit inside an otherwise-Latin word;
    # genuine Russian/Greek prose should not be flagged as evasion.
    homoglyph_hits = 0
    for word in re.findall(r"\w+", working):
        has_latin = any("a" <= c.lower() <= "z" for c in word)
        confusables = sum(c in HOMOGLYPHS for c in word)
        if has_latin and confusables:
            homoglyph_hits += confusables
    if homoglyph_hits:
        evasions.append("homoglyphs")
        working = "".join(HOMOGLYPHS.get(c, c) for c in working)

    lowered = working.lower()

    # Leetspeak: only fold digits that are wedged between letters ("1gn0re"),
    # so version numbers and prices stay intact.
    def _fold(match: re.Match[str]) -> str:
        return match.group(0).translate(LEET)

    folded = re.sub(r"\b(?=[a-z0-9@$]*[a-z])(?=[a-z0-9@$]*[0-9@$])[a-z0-9@$]{3,}\b", _fold, lowered)
    if folded != lowered:
        evasions.append("leetspeak")

    # Collapse "i g n o r e" style letter spacing.
    def _join_spaced(match: re.Match[str]) -> str:
        return match.group(0).replace(" ", "").replace(".", "").replace("-", "")

    despaced = re.sub(r"\b(?:[a-z][ .\-]){4,}[a-z]\b", _join_spaced, folded)
    if despaced != folded:
        evasions.append("letter_spacing")

    collapsed = re.sub(r"[ \t]+", " ", despaced)

    decoded = _decode_b64_candidates(working)
    if decoded:
        evasions.append("base64_payload")

    return NormalizedText(
        original=text,
        text=collapsed,
        evasions=evasions,
        decoded_payloads=decoded,
        hidden_payload=hidden.lower(),
    )
