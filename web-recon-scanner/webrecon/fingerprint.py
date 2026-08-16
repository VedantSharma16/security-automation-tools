"""Lightweight technology fingerprinting from HTTP headers and page HTML.

Signature-based, similar in spirit to Wappalyzer/BuiltWith but intentionally
small and dependency-free — a JSON file of (header/HTML regex -> technology)
signatures that's easy to read, extend, and unit test.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SIGNATURES_PATH = Path(__file__).resolve().parent.parent / "data" / "tech_signatures.json"


@dataclass(frozen=True)
class TechMatch:
    name: str
    category: str
    evidence: str


def load_signatures(path: Path = DEFAULT_SIGNATURES_PATH) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _lower_map(headers: dict) -> dict:
    return {k.lower(): v for k, v in headers.items()}


def fingerprint(headers: dict, html: str, signatures: list) -> list:
    """Match `headers`/`html` against `signatures`, returning one TechMatch
    per signature that hit (header patterns are checked before HTML ones,
    since they're cheaper and more reliable).
    """
    matches = []
    lower_headers = _lower_map(headers or {})
    html = html or ""

    for sig in signatures:
        evidence = None

        for header_name, pattern in sig.get("header_patterns", {}).items():
            value = lower_headers.get(header_name.lower())
            if value and re.search(pattern, value, re.IGNORECASE):
                evidence = f"header {header_name}: {value}"
                break

        if evidence is None:
            for pattern in sig.get("html_patterns", []):
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    evidence = f"html match: {match.group(0)[:80]!r}"
                    break

        if evidence is not None:
            matches.append(TechMatch(name=sig["name"], category=sig.get("category", "unknown"), evidence=evidence))

    return matches
