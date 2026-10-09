"""Rule loading, validation and single-event matching."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import condition as cond
from .matchers import MatcherError, match_field, split_field

LEVELS = ("informational", "low", "medium", "high", "critical")
_TIMESPAN = re.compile(r"^(\d+)([smhd])$")
_TECH = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
_TACTIC_PREFIX = "attack."


class RuleError(ValueError):
    pass


def parse_timespan(text: str) -> int:
    m = _TIMESPAN.match(str(text).strip().lower())
    if not m:
        raise RuleError(f"invalid timeframe {text!r} (use e.g. 30s, 5m, 1h, 1d)")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


@dataclass
class Aggregation:
    """``count() by <field> > N`` within ``timeframe`` seconds."""
    threshold: int
    timeframe: int
    group_by: str | None = None


@dataclass
class Rule:
    id: str
    title: str
    level: str
    detection: dict[str, Any]
    condition: cond.Node
    description: str = ""
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    aggregation: Aggregation | None = None
    source: str = ""

    @property
    def techniques(self) -> list[str]:
        return sorted({m.group(1).upper() for t in self.tags if (m := _TECH.match(t))})

    @property
    def tactics(self) -> list[str]:
        return sorted(
            t[len(_TACTIC_PREFIX):] for t in self.tags
            if t.startswith(_TACTIC_PREFIX) and not _TECH.match(t)
        )

    def selection_matches(self, name: str, event: dict) -> bool:
        sel = self.detection[name]
        if isinstance(sel, dict):
            return all(match_field(event, k, v) for k, v in sel.items())
        # list of maps -> OR; list of plain strings -> keyword search over all values
        for item in sel:
            if isinstance(item, dict):
                if all(match_field(event, k, v) for k, v in item.items()):
                    return True
            elif any(str(item).lower() in str(v).lower() for v in event.values()):
                return True
        return False

    def matches(self, event: dict) -> bool:
        cache: dict[str, bool] = {}

        def lookup(name: str) -> bool:
            if name not in cache:
                cache[name] = self.selection_matches(name, event)
            return cache[name]

        return cond.evaluate(self.condition, lookup, self.detection_selections)

    @property
    def detection_selections(self) -> dict[str, Any]:
        return {k: v for k, v in self.detection.items() if k not in ("condition", "timeframe")}


_AGG = re.compile(r"^\s*(?P<base>.+?)\s*\|\s*count\(\s*\)\s*(?:by\s+(?P<by>\S+)\s*)?>=?\s*(?P<n>\d+)\s*$", re.I)


def _split_aggregation(text: str, timeframe: str | None) -> tuple[str, Aggregation | None]:
    if "|" not in text:
        return text, None
    m = _AGG.match(text)
    if not m:
        raise RuleError(f"unsupported aggregation in condition {text!r}")
    if not timeframe:
        raise RuleError("aggregation requires detection.timeframe")
    n = int(m.group("n"))
    if ">=" not in text:
        n += 1  # '> N' means at least N+1 events
    return m.group("base"), Aggregation(n, parse_timespan(timeframe), m.group("by"))


def build_rule(data: dict, source: str = "") -> Rule:
    if not isinstance(data, dict):
        raise RuleError(f"{source}: rule must be a mapping")
    for key in ("title", "detection"):
        if key not in data:
            raise RuleError(f"{source}: missing required key '{key}'")
    det = data["detection"]
    if not isinstance(det, dict) or "condition" not in det:
        raise RuleError(f"{source}: detection needs a 'condition'")
    level = str(data.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"{source}: level must be one of {', '.join(LEVELS)}")
    base, agg = _split_aggregation(str(det["condition"]), det.get("timeframe"))
    try:
        node = cond.parse(base)
    except cond.ConditionError as exc:
        raise RuleError(f"{source}: bad condition: {exc}") from exc
    rule = Rule(
        id=str(data.get("id", data["title"])), title=data["title"], level=level,
        detection=det, condition=node, description=data.get("description", ""),
        tags=list(data.get("tags", [])), falsepositives=list(data.get("falsepositives", [])),
        aggregation=agg, source=source,
    )
    sels = rule.detection_selections
    for ref in cond.referenced_names(node):
        if "*" in ref or ref.lower() == "them":
            continue
        if ref not in sels:
            raise RuleError(f"{source}: condition references undefined selection '{ref}'")
    for name, sel in sels.items():
        items = [sel] if isinstance(sel, dict) else sel
        if not isinstance(items, list):
            raise RuleError(f"{source}: selection '{name}' must be a map or list")
        for item in items:
            if isinstance(item, dict):
                try:
                    for k in item:
                        split_field(k)
                except MatcherError as exc:
                    raise RuleError(f"{source}: {exc}") from exc
    return rule


def load_rules(path: str | Path) -> list[Rule]:
    """Load one rule file or every ``*.yml``/``*.yaml`` file beneath a directory."""
    p = Path(path)
    files = sorted(f for f in p.rglob("*") if f.suffix in (".yml", ".yaml")) if p.is_dir() else [p]
    rules: list[Rule] = []
    for f in files:
        try:
            docs = list(yaml.safe_load_all(f.read_text(encoding="utf-8")))
        except yaml.YAMLError as exc:
            raise RuleError(f"{f}: invalid YAML: {exc}") from exc
        rules.extend(build_rule(d, str(f)) for d in docs if d)
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"duplicate rule id(s): {', '.join(sorted(dupes))}")
    return rules
