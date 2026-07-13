"""Defang/refang helpers for safely sharing indicators of compromise.

Analysts "defang" IOCs (e.g. ``1.2.3.4`` -> ``1[.]2[.]3[.]4``) before pasting
them into tickets, emails or chat so that mail filters and clients don't treat
them as live links, and threat reports commonly arrive already defanged. This
module converts between the two forms.
"""

from __future__ import annotations

import re

_DEFANG_RULES = [
    (re.compile(r"\."), "[.]"),
    (re.compile(r"https://", re.IGNORECASE), "hxxps://"),
    (re.compile(r"http://", re.IGNORECASE), "hxxp://"),
    (re.compile(r"@"), "[at]"),
]

_REFANG_RULES = [
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"hxxps://", re.IGNORECASE), "https://"),
    (re.compile(r"hxxp://", re.IGNORECASE), "http://"),
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\[@\]"), "@"),
]


def defang(text: str) -> str:
    """Convert live indicators into a safe-to-paste, non-clickable form."""
    # Scheme substitutions must run before the generic dot substitution,
    # otherwise "http://" would already have its dots replaced.
    result = text
    result = _DEFANG_RULES[1][0].sub(_DEFANG_RULES[1][1], result)
    result = _DEFANG_RULES[2][0].sub(_DEFANG_RULES[2][1], result)
    result = _DEFANG_RULES[0][0].sub(_DEFANG_RULES[0][1], result)
    result = _DEFANG_RULES[3][0].sub(_DEFANG_RULES[3][1], result)
    return result


def refang(text: str) -> str:
    """Reverse :func:`defang`, restoring indicators to their live form."""
    result = text
    for pattern, replacement in _REFANG_RULES:
        result = pattern.sub(replacement, result)
    return result
