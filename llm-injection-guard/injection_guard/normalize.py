"""Text normalization that undoes common prompt-injection obfuscation.

Attackers rarely send ``ignore previous instructions`` in plain ASCII any more.
Before running detectors we canonicalise the text and record *what* we had to
undo, because the obfuscation itself is a strong signal:

* Zero-width characters (U+200B etc.) used to split trigger words.
* Bidirectional overrides (U+202E etc.) that make text render differently
  from how a model tokenises it ("Trojan Source"-style).
* Unicode *tag* characters (U+E0000-U+E007F), which are invisible in most UIs
  but are still read by LLMs - so-called "ASCII smuggling". We decode them
  back to ASCII so the hidden payload can be scanned.
* Mixed-script homoglyphs (Cyrillic ``а`` in an otherwise Latin word).
* Letter-spacing (``i g n o r e``) used to dodge keyword matching.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH = frozenset("​‌‍⁠﻿᠎­")
BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩")
TAG_START, TAG_END = 0xE0000, 0xE007F
BLACK_FLAG = "\U0001F3F4"  # subdivision flags (e.g. England) legitimately use tag chars

# Confusable characters that survive NFKC, mapped to their Latin look-alike.
HOMOGLYPHS = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ո": "n",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "ν": "v", "τ": "t",
    "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
}

_WORD = re.compile(r"\w+", re.UNICODE)
# Runs of 4+ single word-characters separated by one space/dot/dash/underscore.
_SPACED = re.compile(r"(?<!\w)(?:\w[ .\-_]){3,}\w(?!\w)")


@dataclass
class NormalizedText:
    original: str
    text: str
    despaced: str
    hidden_tag_text: str = ""
    zero_width_count: int = 0
    bidi_count: int = 0
    tag_char_count: int = 0
    mixed_script_words: list[str] = field(default_factory=list)


def _decode_tag_chars(text: str) -> tuple[str, str, int]:
    """Strip Unicode tag characters, returning (clean_text, decoded_hidden, count).

    Tag sequences that follow U+1F3F4 are emoji subdivision flags and are kept.
    """
    out: list[str] = []
    hidden: list[str] = []
    count = 0
    in_flag = False
    for ch in text:
        cp = ord(ch)
        if TAG_START <= cp <= TAG_END:
            if in_flag:
                out.append(ch)
                if cp == TAG_END:
                    in_flag = False
                continue
            count += 1
            if 0x20 <= cp - TAG_START <= 0x7E:
                hidden.append(chr(cp - TAG_START))
            continue
        in_flag = ch == BLACK_FLAG
        out.append(ch)
    return "".join(out), "".join(hidden), count


def _is_mixed_script(word: str) -> bool:
    has_latin = has_other = False
    for ch in word:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        if name.startswith("LATIN"):
            has_latin = True
        elif name.startswith(("CYRILLIC", "GREEK")):
            has_other = True
    return has_latin and has_other


def _despace(text: str) -> str:
    return _SPACED.sub(lambda m: re.sub(r"[ .\-_]", "", m.group(0)), text)


def normalize(text: str) -> NormalizedText:
    without_tags, hidden, tag_count = _decode_tag_chars(text)

    zw = sum(1 for ch in without_tags if ch in ZERO_WIDTH)
    bidi = sum(1 for ch in without_tags if ch in BIDI_CONTROLS)
    cleaned = "".join(ch for ch in without_tags if ch not in ZERO_WIDTH and ch not in BIDI_CONTROLS)

    cleaned = unicodedata.normalize("NFKC", cleaned)
    mixed = [w for w in _WORD.findall(cleaned) if _is_mixed_script(w)]
    cleaned = "".join(HOMOGLYPHS.get(ch, ch) for ch in cleaned)

    return NormalizedText(
        original=text,
        text=cleaned,
        despaced=_despace(cleaned),
        hidden_tag_text=hidden,
        zero_width_count=zw,
        bidi_count=bidi,
        tag_char_count=tag_count,
        mixed_script_words=mixed,
    )
