"""Input normalization: defeats common obfuscation before pattern matching.

Attackers hide injections with zero-width characters, homoglyphs, leetspeak
and encoded blobs. We produce a canonical view of the text plus any decoded
payloads, and report which obfuscations were present (itself a signal).
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"))
BIDI_CONTROLS = re.compile("[‪-‮⁦-⁩]")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def normalize(text: str) -> tuple[str, list[str]]:
    """Return (canonical_text, obfuscation_flags)."""
    flags: list[str] = []
    if any(ord(c) in ZERO_WIDTH for c in text):
        flags.append("zero_width_chars")
    if BIDI_CONTROLS.search(text):
        flags.append("bidi_controls")
    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        flags.append("unicode_compat_forms")
    out = BIDI_CONTROLS.sub("", nfkc.translate(ZERO_WIDTH))
    # Cyrillic/Greek lookalikes mixed into Latin words
    if re.search(r"[A-Za-z][Ͱ-ϿЀ-ӿ]|[Ͱ-ϿЀ-ӿ][A-Za-z]", out):
        flags.append("mixed_script")
        out = out.translate(_HOMOGLYPHS)
    return out, flags


_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "Ѕ": "S", "І": "I",
    "ο": "o", "α": "a", "ρ": "p",
})


def leet_fold(text: str) -> str:
    """Fold leetspeak only for words that mix letters and digits/symbols."""
    def fix(m: re.Match) -> str:
        w = m.group(0)
        return w.translate(LEET) if re.search(r"[A-Za-z]", w) and re.search(r"[01345 7@$]", w) else w
    return re.sub(r"\S+", fix, text)


def decode_payloads(text: str, max_depth: int = 2) -> list[tuple[str, str]]:
    """Find base64 / hex / rot13 blobs that decode to readable text.

    Returns [(encoding, decoded_text)], recursing up to ``max_depth``.
    """
    found: list[tuple[str, str]] = []

    def printable(s: str) -> bool:
        return len(s) >= 8 and sum(c.isprintable() or c in "\n\t" for c in s) / len(s) > 0.95

    def walk(t: str, depth: int) -> None:
        if depth > max_depth:
            return
        for m in B64_RE.finditer(t):
            try:
                dec = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if printable(dec):
                found.append(("base64", dec))
                walk(dec, depth + 1)
        for m in re.finditer(r"(?:0x)?((?:[0-9a-fA-F]{2}){12,})", t):
            try:
                dec = bytes.fromhex(m.group(1)).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if printable(dec):
                found.append(("hex", dec))
                walk(dec, depth + 1)
        if re.search(r"\brot-?13\b", t, re.I):
            found.append(("rot13", codecs.decode(t, "rot_13")))

    walk(t=text, depth=0)
    return found
