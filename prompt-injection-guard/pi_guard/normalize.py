"""Text normalization that strips the evasion layers attackers wrap around
prompt-injection payloads before the rule engine sees them.

Each step records what it found, because the *presence* of an evasion
technique (invisible characters, Unicode tag smuggling, homoglyphs) is itself
a strong signal — benign text almost never contains them.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

# Zero-width and other invisible formatting characters commonly used to split
# keywords ("ig​nore") so naive substring filters miss them.
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

# Bidirectional control characters ("Trojan Source", CVE-2021-42574) can make
# text render differently from how a model tokenizes it.
BIDI_CONTROLS = {
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
}

# Unicode "tag" block (U+E0000-U+E007F). Each tag character mirrors an ASCII
# character but renders as nothing, so a whole instruction can be smuggled
# invisibly inside otherwise innocent text ("ASCII smuggling").
TAG_START, TAG_END = 0xE0000, 0xE007F

# Small, high-value confusables map: Cyrillic/Greek letters that are visually
# identical to Latin ones. Not exhaustive — enough to defeat the common
# "іgnore рrevious" trick without false-positiving on genuine non-Latin text
# (we only fold when a token mixes scripts; see `_fold_mixed_script_token`).
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k",
    "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
}

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


@dataclass
class NormalizationResult:
    original: str
    normalized: str
    zero_width_count: int = 0
    bidi_count: int = 0
    tag_smuggled_text: str = ""
    homoglyph_tokens: list[str] = field(default_factory=list)

    @property
    def evasion_signals(self) -> list[str]:
        signals = []
        if self.zero_width_count:
            signals.append(f"{self.zero_width_count} zero-width/invisible character(s)")
        if self.bidi_count:
            signals.append(f"{self.bidi_count} bidirectional control character(s)")
        if self.tag_smuggled_text:
            signals.append("Unicode tag-block smuggled text")
        if self.homoglyph_tokens:
            signals.append(f"{len(self.homoglyph_tokens)} mixed-script homoglyph token(s)")
        return signals


def _decode_tag_chars(text: str) -> tuple[str, str]:
    """Remove Unicode tag characters, returning (cleaned_text, smuggled_ascii)."""
    cleaned, smuggled = [], []
    for ch in text:
        cp = ord(ch)
        if TAG_START <= cp <= TAG_END:
            ascii_cp = cp - TAG_START
            if 0x20 <= ascii_cp <= 0x7E:
                smuggled.append(chr(ascii_cp))
        else:
            cleaned.append(ch)
    return "".join(cleaned), "".join(smuggled)


def _is_latin(ch: str) -> bool:
    return ch.isascii() and ch.isalpha()


def _fold_mixed_script_token(token: str) -> tuple[str, bool]:
    """Fold confusables only inside tokens that mix Latin with look-alikes.

    A purely Cyrillic word is left untouched (it is genuine Russian, say), but
    "іgnore" — Cyrillic і followed by Latin "gnore" — is an evasion attempt.
    """
    has_latin = any(_is_latin(c) for c in token)
    has_confusable = any(c in CONFUSABLES for c in token)
    if has_latin and has_confusable:
        return "".join(CONFUSABLES.get(c, c) for c in token), True
    return token, False


def normalize(text: str) -> NormalizationResult:
    result = NormalizationResult(original=text, normalized=text)

    stripped, smuggled = _decode_tag_chars(text)
    result.tag_smuggled_text = smuggled

    chars = []
    for ch in stripped:
        if ch in ZERO_WIDTH:
            result.zero_width_count += 1
            continue
        if ch in BIDI_CONTROLS:
            result.bidi_count += 1
            continue
        chars.append(ch)
    cleaned = "".join(chars)

    # NFKC folds full-width letters (ｉｇｎｏｒｅ), ligatures and other
    # compatibility forms into their plain equivalents.
    cleaned = unicodedata.normalize("NFKC", cleaned)

    folded_tokens = []
    for token in cleaned.split(" "):
        folded, was_mixed = _fold_mixed_script_token(token)
        if was_mixed:
            result.homoglyph_tokens.append(token)
        folded_tokens.append(folded)
    cleaned = " ".join(folded_tokens)

    if smuggled:
        # Append the smuggled payload so the rule engine scans it too.
        cleaned = f"{cleaned}\n{smuggled}"

    result.normalized = cleaned
    return result


def leet_fold(text: str) -> str:
    """Undo simple leetspeak (1gn0r3 -> ignore). Applied as a secondary view,
    never as the primary one, because it would mangle numbers and code."""
    return text.translate(LEET)
