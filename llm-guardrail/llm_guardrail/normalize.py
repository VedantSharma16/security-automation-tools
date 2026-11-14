"""Text normalization and de-obfuscation.

Attackers hide injected instructions from humans (and from naive regex
filters) using invisible characters, Unicode "tag" smuggling, look-alike
letters from other scripts, and encodings such as base64. This module undoes
those tricks so the rule engine sees what the model would see, and records
*that* obfuscation was used — which is itself a strong signal of intent.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# Zero-width / invisible formatting characters.
INVISIBLE = {
    0x00AD, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF,
}
# Bidirectional overrides/isolates ("Trojan Source" style reordering).
BIDI_CONTROLS = {0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
# Unicode Tags block: invisible copies of ASCII, used for "ASCII smuggling".
TAG_START, TAG_END = 0xE0000, 0xE007F

# Common Cyrillic/Greek look-alikes folded to Latin before matching.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "ο": "o", "α": "a", "ε": "e",
    "ι": "i", "κ": "k", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "Ο": "O", "Α": "A", "Ε": "E",
})

_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_WORD = re.compile(r"\w+", re.UNICODE)


@dataclass
class NormalizedText:
    original: str
    text: str
    in_word_invisible: int = 0
    invisible_total: int = 0
    bidi_controls: int = 0
    smuggled: str = ""
    mixed_script_words: list[str] = field(default_factory=list)
    decoded_payloads: list[str] = field(default_factory=list)

    @property
    def hidden_variants(self) -> list[tuple[str, str]]:
        """(technique, text) pairs that should be re-scanned by the rule engine."""
        variants = [("ascii_smuggling", self.smuggled)] if self.smuggled.strip() else []
        variants += [("base64", payload) for payload in self.decoded_payloads]
        return variants


def _script(ch: str) -> str | None:
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


def _mixed_script_words(text: str) -> list[str]:
    words = []
    for match in _WORD.finditer(text):
        scripts = {_script(c) for c in match.group()} - {None, "OTHER"}
        if "LATIN" in scripts and len(scripts) > 1:
            words.append(match.group())
    return words


def _looks_like_text(raw: bytes) -> str | None:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(decoded) < 12 or " " not in decoded:
        return None
    printable = sum(1 for c in decoded if c.isprintable() or c in "\n\t")
    return decoded if printable / len(decoded) >= 0.9 else None


def decode_base64_payloads(text: str) -> list[str]:
    payloads = []
    for match in _BASE64_CANDIDATE.finditer(text):
        token = match.group()
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = _looks_like_text(raw)
        if decoded:
            payloads.append(decoded)
    return payloads


def normalize(text: str) -> NormalizedText:
    kept: list[str] = []
    smuggled: list[str] = []
    in_word = invisible = bidi = 0

    for i, ch in enumerate(text):
        cp = ord(ch)
        if TAG_START <= cp <= TAG_END:
            if 0xE0020 <= cp <= 0xE007E:
                smuggled.append(chr(cp - TAG_START))
            continue
        if cp in BIDI_CONTROLS:
            bidi += 1
            continue
        if cp in INVISIBLE:
            invisible += 1
            prev_ch = text[i - 1] if i > 0 else ""
            next_ch = text[i + 1] if i + 1 < len(text) else ""
            # Zero-width chars wedged inside a word are an evasion signal; a
            # ZWJ between emoji is just how modern emoji are encoded.
            if prev_ch.isalpha() and next_ch.isalpha():
                in_word += 1
            continue
        kept.append(ch)

    cleaned = "".join(kept)
    mixed = _mixed_script_words(cleaned)
    folded = unicodedata.normalize("NFKC", cleaned).translate(CONFUSABLES)

    return NormalizedText(
        original=text,
        text=folded,
        in_word_invisible=in_word,
        invisible_total=invisible,
        bidi_controls=bidi,
        smuggled="".join(smuggled),
        mixed_script_words=mixed,
        decoded_payloads=decode_base64_payloads(folded),
    )
