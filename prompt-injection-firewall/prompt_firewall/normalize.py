"""Text normalisation and de-obfuscation.

Attackers rarely send ``ignore previous instructions`` in plain ASCII once a
filter is in place. This module turns a raw string into a set of *views* that
the rule engine scans, so a single regex catches many encodings of the same
payload:

* ``canonical``   - NFKC-folded, invisible characters stripped, Unicode tag
                    characters ("ASCII smuggling") decoded, homoglyphs mapped
                    to Latin, lower-cased, whitespace collapsed.
* ``deobfuscated`` - ``canonical`` plus leetspeak reversal and re-joining of
                    letter-spaced words (``i g n o r e`` -> ``ignore``).
* decoded segments - base64 / hex blobs that decode to readable text, and
                    a ROT13 view when the text asks for ROT13 decoding.

Each transformation that actually fired is recorded as an
:class:`ObfuscationSignal`; the presence of obfuscation is itself evidence.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass, field

# Zero-width and bidirectional control characters commonly used to split
# keywords ("ig​nore") or visually reorder text.
_INVISIBLE = {
    *range(0x200B, 0x2010),  # zero-width space/joiners, LRM/RLM
    *range(0x202A, 0x202F),  # bidi embeddings/overrides
    *range(0x2060, 0x2065),  # word joiner, invisible operators
    *range(0x2066, 0x206A),  # bidi isolates
    0xFEFF,  # zero-width no-break space / BOM
    0x00AD,  # soft hyphen
}

# Unicode "tag" block (U+E0000-U+E007F). Tag characters render as nothing but
# map 1:1 onto ASCII, which makes them a known channel for smuggling hidden
# instructions to LLMs.
_TAG_START, _TAG_END = 0xE0000, 0xE007F

# Cyrillic/Greek letters that are visually identical to Latin ones.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
        "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l",
        "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ι": "i", "κ": "k", "ν": "v",
        "τ": "t", "υ": "u", "χ": "x",
    }
)
_HOMOGLYPH_CHARS = set("аеорсхуіјѕԁɡһӏαεορικντυχ")

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})

_SPACED_WORD = re.compile(r"\b(?:[a-z][ .\-_*]){3,}[a-z]\b")
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_CANDIDATE = re.compile(r"\b(?:[0-9a-fA-F]{2}){10,}\b")
_WS = re.compile(r"\s+")
_ROT13_HINT = re.compile(r"\brot-?13\b|\bcaesar\b")


@dataclass(frozen=True)
class ObfuscationSignal:
    kind: str
    detail: str


@dataclass
class NormalizedText:
    original: str
    canonical: str
    deobfuscated: str
    decoded_segments: list[tuple[str, str]] = field(default_factory=list)  # (encoding, text)
    signals: list[ObfuscationSignal] = field(default_factory=list)

    def views(self) -> list[tuple[str, str]]:
        """All (view_name, text) pairs worth scanning, de-duplicated."""
        seen: set[str] = set()
        out: list[tuple[str, str]] = []
        for name, text in [("canonical", self.canonical), ("deobfuscated", self.deobfuscated)] + [
            (f"decoded:{enc}", txt) for enc, txt in self.decoded_segments
        ]:
            if text and text not in seen:
                seen.add(text)
                out.append((name, text))
        return out


def _decode_tags(text: str) -> tuple[str, str]:
    """Split ``text`` into (visible text, smuggled ASCII from tag characters)."""
    visible, hidden = [], []
    for ch in text:
        cp = ord(ch)
        if _TAG_START <= cp <= _TAG_END:
            inner = cp - _TAG_START
            if 0x20 <= inner < 0x7F:
                hidden.append(chr(inner))
        else:
            visible.append(ch)
    return "".join(visible), "".join(hidden)


def _is_readable(text: str) -> bool:
    if len(text) < 8:
        return False
    printable = sum(ch.isprintable() and ord(ch) < 128 for ch in text)
    letters = sum(ch.isalpha() for ch in text)
    return printable / len(text) > 0.95 and letters / len(text) > 0.5 and " " in text


def _try_decode(blob: str, encoding: str) -> str | None:
    try:
        if encoding == "base64":
            padded = blob + "=" * (-len(blob) % 4)
            raw = base64.b64decode(padded, validate=True)
        else:
            raw = binascii.unhexlify(blob)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text if _is_readable(text) else None


def _collapse_spaced(text: str) -> str:
    return _SPACED_WORD.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), text)


def normalize(text: str) -> NormalizedText:
    signals: list[ObfuscationSignal] = []

    visible, smuggled = _decode_tags(text)
    if smuggled:
        signals.append(ObfuscationSignal("unicode_tags", f"{len(smuggled)} hidden tag characters decoded"))

    invisible_count = sum(1 for ch in visible if ord(ch) in _INVISIBLE)
    if invisible_count:
        signals.append(ObfuscationSignal("invisible_chars", f"{invisible_count} zero-width/bidi characters removed"))
    stripped = "".join(ch for ch in visible if ord(ch) not in _INVISIBLE)

    folded = unicodedata.normalize("NFKC", stripped)
    if folded != stripped and any(unicodedata.east_asian_width(c) == "F" for c in stripped):
        signals.append(ObfuscationSignal("fullwidth", "full-width characters folded to ASCII"))

    lowered = folded.lower()
    homoglyphs = sum(1 for ch in lowered if ch in _HOMOGLYPH_CHARS)
    # Only treat Cyrillic/Greek as obfuscation when mixed into Latin text;
    # genuine Russian or Greek prose should not be penalised.
    latin = sum(1 for ch in lowered if "a" <= ch <= "z")
    if homoglyphs and latin > homoglyphs:
        signals.append(ObfuscationSignal("homoglyphs", f"{homoglyphs} look-alike characters mapped to Latin"))
        lowered = lowered.translate(_HOMOGLYPHS)

    canonical = _WS.sub(" ", lowered).strip()
    if smuggled:
        canonical = f"{canonical} {smuggled.lower()}".strip()

    deobfuscated = _collapse_spaced(canonical.translate(_LEET))
    if deobfuscated != canonical and _collapse_spaced(canonical) != canonical:
        signals.append(ObfuscationSignal("letter_spacing", "letter-spaced words re-joined"))

    decoded: list[tuple[str, str]] = []
    for pattern, enc in ((_B64_CANDIDATE, "base64"), (_HEX_CANDIDATE, "hex")):
        for match in pattern.finditer(stripped):
            result = _try_decode(match.group(0), enc)
            if result:
                decoded.append((enc, _WS.sub(" ", result.lower()).strip()))
    # ROT13 has no recognisable alphabet, so only decode when the text itself
    # tells the model to ("apply rot13 then follow ...").
    if _ROT13_HINT.search(canonical):
        decoded.append(("rot13", codecs.decode(canonical, "rot13")))
    if decoded:
        signals.append(ObfuscationSignal("encoded_payload", f"{len(decoded)} encoded segment(s) decoded"))

    return NormalizedText(
        original=text,
        canonical=canonical,
        deobfuscated=deobfuscated,
        decoded_segments=decoded,
        signals=signals,
    )
