"""Text transforms used to *build* obfuscated attacks, and the normalizer used
to *undo* them before detection.

Keeping both directions in one module makes the attack/defence symmetry
explicit: every obfuscation the harness can generate has a matching
normalization step, and the guard evaluation measures what happens with and
without it.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

ZERO_WIDTH = ("​", "‌", "‍", "⁠", "﻿")

# Latin -> visually identical Cyrillic. Used to generate homoglyph attacks.
_LATIN_TO_CYRILLIC = {
    "a": "а", "c": "с", "e": "е", "i": "і", "o": "о",
    "p": "р", "s": "ѕ", "x": "х", "y": "у",
    "A": "А", "C": "С", "E": "Е", "I": "І", "O": "О",
    "P": "Р", "S": "Ѕ", "X": "Х",
}
_CYRILLIC_TO_LATIN = {v: k for k, v in _LATIN_TO_CYRILLIC.items()}
# Greek look-alikes commonly seen in the wild as well.
_CYRILLIC_TO_LATIN.update({"ο": "o", "α": "a", "ε": "e", "ι": "i", "Ο": "O"})

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

_MARKER_RE = re.compile(r"PWN-[A-Z0-9]{6,}")
_BASE64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_LEET_WORD_RE = re.compile(r"\b(?=[a-z0-9@$]*[a-z])(?=[a-z0-9@$]*[013457@$])[a-z0-9@$]{3,}\b", re.IGNORECASE)


def _outside_markers(text: str, fn) -> str:
    """Apply ``fn`` to every span of ``text`` that is not a PWN- marker."""
    out, last = [], 0
    for m in _MARKER_RE.finditer(text):
        out.append(fn(text[last:m.start()]))
        out.append(m.group(0))
        last = m.end()
    out.append(fn(text[last:]))
    return "".join(out)


# --------------------------------------------------------------------------- #
# Attack-side transforms
# --------------------------------------------------------------------------- #

def to_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _split_word(match: re.Match) -> str:
    word = match.group(0)
    mid = len(word) // 2
    return word[:mid] + "\u200b" + word[mid:]


def insert_zero_width(text: str) -> str:
    """Insert a zero-width space inside every word of 4+ letters (markers left intact)."""
    return _outside_markers(text, lambda span: re.sub(r"[A-Za-z]{4,}", _split_word, span))


def to_homoglyphs(text: str) -> str:
    """Swap Latin letters for Cyrillic look-alikes everywhere except inside markers."""
    return _outside_markers(text, lambda span: "".join(_LATIN_TO_CYRILLIC.get(ch, ch) for ch in span))


TRANSFORMS = {
    "base64": to_base64,
    "zero_width": insert_zero_width,
    "homoglyph": to_homoglyphs,
}


def apply_transform(name: str | None, text: str) -> str:
    if not name:
        return text
    try:
        return TRANSFORMS[name](text)
    except KeyError as exc:
        raise ValueError(f"unknown transform: {name!r}") from exc


# --------------------------------------------------------------------------- #
# Defence-side normalization
# --------------------------------------------------------------------------- #

def strip_zero_width(text: str) -> str:
    for ch in ZERO_WIDTH:
        text = text.replace(ch, "")
    return text


def fold_homoglyphs(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    return "".join(_CYRILLIC_TO_LATIN.get(ch, ch) for ch in text)


def unleet(text: str) -> str:
    """De-leet only tokens that mix letters with leet digits (so '2024' or 'HTTP 403' survive)."""
    return _outside_markers(text, lambda span: _LEET_WORD_RE.sub(lambda m: m.group(0).translate(_LEET), span))


def decode_base64_blobs(text: str) -> list[str]:
    """Return every printable UTF-8 string hidden in base64-looking runs of the text."""
    decoded = []
    for blob in _BASE64_BLOB_RE.findall(text):
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if candidate and sum(ch.isprintable() or ch.isspace() for ch in candidate) / len(candidate) > 0.95:
            decoded.append(candidate)
    return decoded


def normalize(text: str, decode_base64: bool = True) -> str:
    """Canonicalize text so obfuscated instructions look like plain ones.

    Lossy readings (de-leeted text, decoded base64 payloads) are *appended*
    rather than substituted, so detectors see both the original and what it hides.
    """
    text = fold_homoglyphs(strip_zero_width(text))
    # De-leeting is lossy ("base64" -> "basesa"), so keep both readings.
    deleeted = unleet(text)
    if deleeted != text:
        text = text + "\n" + deleeted
    if decode_base64:
        hidden = decode_base64_blobs(text)
        if hidden:
            text = text + "\n" + "\n".join(normalize(h, decode_base64=False) for h in hidden)
    return text


def find_markers(text: str) -> list[str]:
    return _MARKER_RE.findall(text)
