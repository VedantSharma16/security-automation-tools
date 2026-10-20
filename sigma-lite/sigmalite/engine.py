"""Event loading and rule evaluation."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .rules import LEVELS, Rule


@dataclass
class Match:
    rule: Rule
    event_index: int
    event: dict


def load_events(path: str | Path) -> list[dict]:
    """Load events from a JSON array file or NDJSON (one object per line)."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text[0] == "[":
        data = json.loads(text)
        if not all(isinstance(e, dict) for e in data):
            raise ValueError("JSON array must contain only objects")
        return data
    events = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"line {n}: invalid JSON ({e.msg})") from e
        if not isinstance(obj, dict):
            raise ValueError(f"line {n}: expected a JSON object")
        events.append(obj)
    return events


def evaluate(rules: list[Rule], events: list[dict], min_level: str = "informational") -> list[Match]:
    floor = LEVELS.index(min_level)
    active = [r for r in rules if LEVELS.index(r.level) >= floor]
    return [Match(r, i, e) for i, e in enumerate(events) for r in active if r.matches(e)]


def summarize(matches: list[Match]) -> dict:
    by_rule: dict[str, dict] = {}
    for m in matches:
        entry = by_rule.setdefault(m.rule.id, {
            "id": m.rule.id, "title": m.rule.title, "level": m.rule.level,
            "techniques": m.rule.attack_techniques, "tactics": m.rule.attack_tactics,
            "event_indexes": [],
        })
        entry["event_indexes"].append(m.event_index)
    hits = sorted(by_rule.values(), key=lambda h: (-LEVELS.index(h["level"]), h["title"]))
    return {
        "total_matches": len(matches),
        "rules_triggered": len(hits),
        "techniques": sorted({t for h in hits for t in h["techniques"]}),
        "hits": hits,
    }
