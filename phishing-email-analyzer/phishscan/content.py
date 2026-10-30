"""Social-engineering language heuristics."""
from __future__ import annotations

import re

from .models import Finding

_PATTERNS = [
    ("urgency", r"\b(urgent|immediately|within 24 hours|act now|final notice|account (?:will be )?(?:suspended|locked|closed)|expires? (?:today|soon))\b"),
    ("credential lure", r"\b(verify your (?:account|identity|password)|confirm your (?:password|credentials)|re-?enter your|sign[- ]?in to (?:keep|restore)|password (?:expires|reset))\b"),
    ("financial lure", r"\b(wire transfer|gift cards?|invoice attached|payment (?:failed|overdue)|bank details|bitcoin)\b"),
    ("authority", r"\b(ceo|cfo|it (?:support|helpdesk)|security team)\b"),
]


def analyze_content(subject: str, body: str) -> list[Finding]:
    text = f"{subject}\n{body}"
    hits = [(label, m.group(0)) for label, pat in _PATTERNS for m in [re.search(pat, text, re.I)] if m]
    findings = [Finding("content", "low", f"Social-engineering language: {label}", phrase, "T1566") for label, phrase in hits]
    if len(hits) >= 3:
        findings.append(Finding("content", "medium", "Multiple social-engineering themes combined",
                                ", ".join(l for l, _ in hits)))
    return findings
