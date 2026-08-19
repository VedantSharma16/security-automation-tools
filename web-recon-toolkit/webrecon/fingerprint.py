"""Lightweight technology fingerprinting from HTTP headers and response bodies,
using a small local signature database. No external services or lookups."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DEFAULT_SIGNATURES_PATH = Path(__file__).resolve().parent.parent / "data" / "tech_signatures.json"


@dataclass
class TechMatch:
    name: str
    category: str
    evidence: str


@lru_cache(maxsize=1)
def _load_signatures_cached(path: str) -> tuple[dict, ...]:
    return tuple(json.loads(Path(path).read_text(encoding="utf-8")))


def load_signatures(path: Path | None = None) -> list[dict]:
    return list(_load_signatures_cached(str(path or DEFAULT_SIGNATURES_PATH)))


def identify(headers: dict[str, str], body: str, signatures: list[dict] | None = None) -> list[TechMatch]:
    """Match headers/body against the signature database. Each technology is reported once."""
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    sigs = signatures if signatures is not None else load_signatures()

    matches: list[TechMatch] = []
    seen: set[str] = set()
    for sig in sigs:
        if sig["name"] in seen:
            continue
        rule = sig["match"]
        if rule["type"] == "header":
            target = normalized_headers.get(rule["header"].lower(), "")
        elif rule["type"] == "body":
            target = body
        else:
            continue

        if target and re.search(rule["pattern"], target):
            evidence = target[:120] if rule["type"] == "header" else f"body matched: {rule['pattern']}"
            matches.append(TechMatch(name=sig["name"], category=sig["category"], evidence=evidence))
            seen.add(sig["name"])

    return matches
