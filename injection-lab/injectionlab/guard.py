"""Heuristic input guard: scores text for prompt-injection indicators.

Deliberately transparent (regex rules with weights) so every block decision
can be explained. It also normalises leetspeak and decodes base64 blobs so
simple encoding evasions are inspected in their decoded form.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

# (rule id, regex, weight)
RULES: list[tuple[str, str, float]] = [
    ("override_instructions",
     r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|rules?|prompts?|polic(y|ies))\b", 0.8),
    ("reveal_system_prompt",
     r"\b(reveal|print|show|output|repeat|disclose|leak)\b.{0,40}\b(system prompt|initial instructions|hidden instructions|everything above|your instructions)\b", 0.7),
    ("reveal_secret",
     r"\b(reveal|disclose|output|send|print|give|read)\w*\b.{0,40}\b(secret|confidential|token|password|api key|credentials?)\b", 0.6),
    ("persona_switch",
     r"\b(you are now|pretend (you are|to be)|act as|from now on you)\b|\bDAN\b|no restrictions", 0.5),
    ("fake_role_delimiter",
     r"</?\s*(system|user|assistant)\s*>|#{2,}\s*system|\[\s*(system|instruction to ai)\b", 0.7),
    ("hidden_instruction",
     r"<!--.{0,80}\b(ai|assistant|llm)\b.{0,200}-->|\[instruction to ai", 0.7),
    ("exfil_url",
     r"!\[[^\]]*\]\(https?://[^)]*\?[^)]*\)|send .{0,40}\bto\b .{0,40}@", 0.6),
    ("maintenance_mode", r"\b(maintenance|developer|debug|admin) mode\b", 0.4),
]
_COMPILED = [(n, re.compile(p, re.I | re.S), w) for n, p, w in RULES]

_LEET = str.maketrans("013457$@", "oieastsa")
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


@dataclass
class GuardResult:
    score: float
    blocked: bool
    matched: list[str] = field(default_factory=list)


def _decode_blobs(text: str) -> list[str]:
    out = []
    for blob in _B64.findall(text):
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            out.append(decoded.decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError):
            continue
    return out


def views(text: str) -> list[str]:
    """Return the raw text plus normalised/decoded variants to inspect."""
    vs = [text, text.translate(_LEET)]
    vs.extend(_decode_blobs(text))
    return vs


def scan(text: str, threshold: float = 0.6) -> GuardResult:
    matched: dict[str, float] = {}
    for v in views(text):
        for name, rx, weight in _COMPILED:
            if rx.search(v):
                matched[name] = weight
    # Combine weights as independent evidence: 1 - prod(1 - w)
    remaining = 1.0
    for w in matched.values():
        remaining *= 1 - w
    score = round(1 - remaining, 3)
    return GuardResult(score=score, blocked=score >= threshold, matched=sorted(matched))
