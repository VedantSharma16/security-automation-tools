"""Brand-impersonation detection: display-name spoofing and lookalike /
typosquatted sender domains, checked against a small local brand→domain
table (`data/brands.json`). This is a heuristic, not a public-suffix-list
aware registrable-domain parser — good enough to flag `paypal-secure.com`
or `micros0ft.com`, not a substitute for a real PSL-based tool.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Common leetspeak / homoglyph substitutions used in typosquats, normalized
# to a canonical letter so e.g. "micr0soft" and "microsoft" compare equal.
_HOMOGLYPH_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


@lru_cache(maxsize=1)
def brands() -> dict[str, list[str]]:
    with (_DATA_DIR / "brands.json").open() as fh:
        return {k.lower(): [d.lower() for d in v] for k, v in json.load(fh).items()}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _normalize_homoglyphs(label: str) -> str:
    normalized = label.translate(_HOMOGLYPH_MAP)
    normalized = normalized.replace("rn", "m").replace("vv", "w")
    return normalized


def _second_level_label(domain: str) -> str:
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


@dataclass
class LookalikeMatch:
    brand: str
    official_domain: str
    matched_domain: str
    technique: str  # "substring" | "edit-distance" | "homoglyph"


def check_domain_against_brands(domain: str) -> list[LookalikeMatch]:
    """Flag `domain` if it plausibly impersonates a brand it isn't."""
    if not domain:
        return []
    domain = domain.lower()
    matches: list[LookalikeMatch] = []
    dom_label = _second_level_label(domain)
    dom_stripped = re.sub(r"[^a-z0-9]", "", dom_label)
    # Normalize leetspeak/homoglyphs *before* the substring check too, so a
    # combined attack like "paypa1-support.com" (digit swap + extra words)
    # is still caught rather than needing an exact letter-for-letter match.
    dom_stripped_norm = _normalize_homoglyphs(dom_stripped)

    for brand, official_domains in brands().items():
        if domain in official_domains:
            continue
        if any(domain.endswith("." + off) for off in official_domains):
            continue  # legitimate subdomain, e.g. mail.google.com

        if dom_stripped != brand and brand in dom_stripped:
            matches.append(LookalikeMatch(brand, official_domains[0], domain, "substring"))
            continue
        if dom_stripped_norm != brand and brand in dom_stripped_norm:
            matches.append(LookalikeMatch(brand, official_domains[0], domain, "homoglyph"))
            continue

        matched = False
        for official in official_domains:
            off_label = _second_level_label(official)
            if len(off_label) <= 3:
                continue  # too short to compare safely (false-positive prone)
            dist = _levenshtein(dom_label, off_label)
            if 0 < dist <= 2:
                matches.append(LookalikeMatch(brand, official, domain, "edit-distance"))
                matched = True
                break
            if dom_label != off_label and _normalize_homoglyphs(dom_label) == off_label:
                matches.append(LookalikeMatch(brand, official, domain, "homoglyph"))
                matched = True
                break
        if matched:
            continue

    return matches


def brands_mentioned_in(text: str) -> list[str]:
    """Which known brand names are mentioned (as whole words) in free text,
    e.g. an email's display name or subject line."""
    text_lower = (text or "").lower()
    return [brand for brand in brands() if re.search(rf"\b{re.escape(brand)}\b", text_lower)]
