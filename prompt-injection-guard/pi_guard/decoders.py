"""Find and decode encoded payloads (base64, hex, rot13 markers) so that an
instruction hidden as `aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM=` is scanned
in plaintext. Attackers rely on the model happily decoding these on request.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass

# Long-ish runs only: short base64-looking tokens are everywhere (IDs, hashes).
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}){12,})(?![0-9a-fA-F])")
ROT13_HINT_RE = re.compile(r"rot-?13[^\n:]*[:\-]\s*(.+)", re.IGNORECASE)


@dataclass
class DecodedSegment:
    encoding: str
    encoded: str
    decoded: str


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t")
    return printable / len(text)


def _looks_like_text(decoded: str) -> bool:
    # Require mostly-printable output with at least a couple of words —
    # otherwise we just decoded a random hash or binary blob.
    return _printable_ratio(decoded) > 0.95 and len(decoded.split()) >= 2


def find_encoded_segments(text: str) -> list[DecodedSegment]:
    segments: list[DecodedSegment] = []

    for match in BASE64_RE.finditer(text):
        token = match.group(1)
        padded = token + "=" * (-len(token) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _looks_like_text(decoded):
            segments.append(DecodedSegment("base64", token, decoded))

    for match in HEX_RE.finditer(text):
        token = match.group(1)
        try:
            decoded = bytes.fromhex(token).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(decoded):
            segments.append(DecodedSegment("hex", token, decoded))

    for match in ROT13_HINT_RE.finditer(text):
        token = match.group(1).strip()
        segments.append(DecodedSegment("rot13", token, codecs.decode(token, "rot13")))

    return segments
