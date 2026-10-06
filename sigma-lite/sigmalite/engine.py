"""Replay events against rules and summarise detections."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .rules import LEVELS, Rule


@dataclass
class Detection:
    rule: Rule
    event: dict
    line: int


def read_events(path: str | Path) -> Iterator[tuple[int, dict]]:
    """Yield (line_number, event) from a JSON Lines file; bad lines raise."""
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{n}: invalid JSON ({exc.msg})") from exc
            if not isinstance(ev, dict):
                raise ValueError(f"{path}:{n}: event must be a JSON object")
            yield n, ev


def run(rules: Iterable[Rule], events: Iterable[tuple[int, dict]]) -> list[Detection]:
    rules = list(rules)
    out = []
    for line, ev in events:
        for rule in rules:
            if rule.matches(ev):
                out.append(Detection(rule, ev, line))
    return out


def summarize(detections: list[Detection]) -> dict:
    by_rule = Counter(d.rule.id for d in detections)
    titles = {d.rule.id: d.rule.title for d in detections}
    worst = max((LEVELS.index(d.rule.level) for d in detections), default=-1)
    return {
        "total": len(detections),
        "highest_severity": LEVELS[worst] if worst >= 0 else None,
        "by_rule": [
            {"id": i, "title": titles[i], "count": c} for i, c in by_rule.most_common()
        ],
    }


def coverage(rules: Iterable[Rule]) -> dict[str, list[str]]:
    """Map each ATT&CK technique ID to the rule IDs that cover it."""
    cov: dict[str, list[str]] = {}
    for r in rules:
        for t in r.techniques:
            cov.setdefault(t, []).append(r.id)
    return dict(sorted(cov.items()))
