"""Rule model and loader (JSON rules, Sigma-style detection blocks)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .condition import Condition, ConditionError
from .matcher import MatchError, Selection

LEVELS = ("informational", "low", "medium", "high", "critical")
_TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
_DURATION = re.compile(r"^(\d+)([smhd])$")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class RuleError(ValueError):
    pass


def parse_duration(text: str) -> int:
    m = _DURATION.match(str(text).strip().lower())
    if not m:
        raise RuleError(f"bad timeframe {text!r} (use e.g. 30s, 5m, 1h)")
    return int(m.group(1)) * _UNIT[m.group(2)]


@dataclass
class Threshold:
    count: int
    window_seconds: int
    group_by: list[str] = field(default_factory=list)


@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str
    tags: list[str]
    selections: dict[str, Selection]
    condition: Condition
    threshold: Threshold | None = None
    tests: dict = field(default_factory=dict)
    source: str = ""

    @property
    def techniques(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if _TECHNIQUE.match(t)]

    @property
    def tactics(self) -> list[str]:
        return [
            t.split(".", 1)[1]
            for t in self.tags
            if t.startswith("attack.") and not _TECHNIQUE.match(t)
        ]

    def matches(self, event: dict) -> bool:
        cache: dict[str, bool] = {}

        def hit(name: str) -> bool:
            if name not in cache:
                cache[name] = self.selections[name].matches(event)
            return cache[name]

        return self.condition.evaluate(hit)


def parse_rule(data: dict, source: str = "") -> Rule:
    where = f"{source or 'rule'}"
    for key in ("id", "title", "level", "detection"):
        if key not in data:
            raise RuleError(f"{where}: missing required key '{key}'")
    if data["level"] not in LEVELS:
        raise RuleError(f"{where}: level must be one of {LEVELS}")
    det = dict(data["detection"])
    cond_text = det.pop("condition", None)
    if not cond_text:
        raise RuleError(f"{where}: detection.condition is required")
    if not det:
        raise RuleError(f"{where}: detection has no selections")
    try:
        selections = {name: Selection(spec) for name, spec in det.items()}
        condition = Condition(cond_text, set(selections))
    except (MatchError, ConditionError) as exc:
        raise RuleError(f"{where}: {exc}") from exc

    threshold = None
    if "threshold" in data:
        t = data["threshold"]
        count = t.get("count")
        if not isinstance(count, int) or count < 2:
            raise RuleError(f"{where}: threshold.count must be an integer >= 2")
        threshold = Threshold(count, parse_duration(t.get("timeframe", "")), list(t.get("group_by", [])))

    return Rule(
        id=str(data["id"]),
        title=data["title"],
        level=data["level"],
        description=data.get("description", ""),
        tags=list(data.get("tags", [])),
        selections=selections,
        condition=condition,
        threshold=threshold,
        tests=data.get("tests", {}),
        source=source,
    )


def load_rules(path: str | Path) -> list[Rule]:
    """Load one rule file or every ``*.json`` under a directory."""
    p = Path(path)
    files = sorted(p.rglob("*.json")) if p.is_dir() else [p]
    if not files:
        raise RuleError(f"no rule files found in {p}")
    rules, seen = [], set()
    for f in files:
        try:
            data = json.loads(f.read_text())
        except json.JSONDecodeError as exc:
            raise RuleError(f"{f}: invalid JSON ({exc})") from exc
        for item in data if isinstance(data, list) else [data]:
            rule = parse_rule(item, str(f))
            if rule.id in seen:
                raise RuleError(f"{f}: duplicate rule id {rule.id}")
            seen.add(rule.id)
            rules.append(rule)
    return rules
