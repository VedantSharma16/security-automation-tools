"""Run a rule set over a stream of JSON events."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Iterator

from .rule import LEVELS, Rule


@dataclass
class Match:
    rule: Rule
    event: dict
    line: int

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule.id, "title": self.rule.title, "level": self.rule.level,
            "techniques": self.rule.attack_techniques, "tactics": self.rule.attack_tactics,
            "line": self.line, "event": self.event,
        }


class Engine:
    def __init__(self, rules: Iterable[Rule]):
        self.rules = list(rules)

    def scan(self, events: Iterable[dict]) -> Iterator[Match]:
        for n, ev in enumerate(events, 1):
            for rule in self.rules:
                if rule.matches(ev):
                    yield Match(rule, ev, n)


def read_jsonl(lines: Iterable[str]) -> Iterator[dict]:
    """Yield dict events from JSON-lines; also accepts a single JSON array line stream."""
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue  # tolerate junk lines in real-world logs
        if isinstance(obj, dict):
            yield obj


def summarize(matches: list[Match]) -> dict:
    by_level = Counter(m.rule.level for m in matches)
    by_tech = Counter(t for m in matches for t in m.rule.attack_techniques)
    top = max((LEVELS.index(m.rule.level) for m in matches), default=-1)
    return {
        "total_matches": len(matches),
        "by_level": {l: by_level[l] for l in reversed(LEVELS) if by_level[l]},
        "by_technique": dict(by_tech.most_common()),
        "highest_severity": LEVELS[top] if top >= 0 else None,
    }
