"""Rule model, field matching with modifiers, and rule loading/validation."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from . import condition as cond

LEVELS = ("informational", "low", "medium", "high", "critical")
MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cidr", "gt", "gte", "lt", "lte", "exists"}
_TECH = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.I)


class RuleError(ValueError):
    pass


def get_field(event: dict, path: str) -> Any:
    """Resolve dotted paths; fall back to a literal key containing dots."""
    if path in event:
        return event[path]
    cur: Any = event
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _as_list(v):
    return v if isinstance(v, list) else [v]


class FieldMatcher:
    def __init__(self, key: str, expected: Any):
        field_name, *mods = key.split("|")
        bad = [m for m in mods if m not in MODIFIERS]
        if bad:
            raise RuleError(f"unknown modifier(s) {bad} in {key!r}")
        self.field, self.mods = field_name, mods
        self.require_all = "all" in mods
        self.op = next((m for m in mods if m != "all"), "equals")
        self.values = _as_list(expected)
        if self.op == "re":
            try:
                self._res = [re.compile(str(v)) for v in self.values]
            except re.error as e:
                raise RuleError(f"bad regex in {key!r}: {e}") from e
        elif self.op == "cidr":
            try:
                self._nets = [ipaddress.ip_network(str(v), strict=False) for v in self.values]
            except ValueError as e:
                raise RuleError(f"bad CIDR in {key!r}: {e}") from e
        elif self.op in ("gt", "gte", "lt", "lte"):
            try:
                self.values = [float(v) for v in self.values]
            except (TypeError, ValueError) as e:
                raise RuleError(f"numeric value required for {key!r}") from e

    def _one(self, actual: Any, i: int) -> bool:
        op, exp = self.op, self.values[i]
        if op == "exists":
            return (actual is not None) == bool(exp)
        if actual is None:
            return exp is None and op == "equals"
        if op == "equals":
            if isinstance(actual, str) and isinstance(exp, str):
                return actual.lower() == exp.lower()
            return actual == exp
        if op == "re":
            return self._res[i].search(str(actual)) is not None
        if op == "cidr":
            try:
                return ipaddress.ip_address(str(actual)) in self._nets[i]
            except ValueError:
                return False
        if op in ("gt", "gte", "lt", "lte"):
            try:
                a = float(actual)
            except (TypeError, ValueError):
                return False
            return {"gt": a > exp, "gte": a >= exp, "lt": a < exp, "lte": a <= exp}[op]
        a, e = str(actual).lower(), str(exp).lower()
        return {"contains": e in a, "startswith": a.startswith(e), "endswith": a.endswith(e)}[op]

    def matches(self, event: dict) -> bool:
        actual = get_field(event, self.field)
        hits = (self._one(actual, i) for i in range(len(self.values)))
        return all(hits) if self.require_all else any(hits)


class Selection:
    """A selection is a dict (AND of fields) or a list of dicts (OR of maps)."""

    def __init__(self, name: str, spec: Any):
        maps = spec if isinstance(spec, list) else [spec]
        if not maps or not all(isinstance(m, dict) and m for m in maps):
            raise RuleError(f"selection {name!r} must be a non-empty mapping or list of mappings")
        self.name = name
        self.maps = [[FieldMatcher(k, v) for k, v in m.items()] for m in maps]

    def matches(self, event: dict) -> bool:
        return any(all(f.matches(event) for f in m) for m in self.maps)


@dataclass
class Rule:
    id: str
    title: str
    level: str
    condition: str
    selections: dict[str, Selection]
    description: str = ""
    tags: list[str] = field(default_factory=list)
    tests: dict = field(default_factory=dict)
    source: str = ""

    def __post_init__(self):
        self._ast = cond.parse(self.condition)
        unknown = cond.referenced_names(self._ast, self.selections) - set(self.selections)
        if unknown:
            raise RuleError(f"{self.id}: condition references undefined selection(s) {sorted(unknown)}")

    @property
    def techniques(self) -> list[str]:
        return sorted({t.split(".", 1)[1].upper() for t in self.tags if _TECH.match(t)})

    def matches(self, event: dict) -> bool:
        cache: dict[str, bool] = {}

        def look(n: str) -> bool:
            if n not in cache:
                cache[n] = self.selections[n].matches(event)
            return cache[n]

        return cond.evaluate(self._ast, look, self.selections)

    @classmethod
    def from_dict(cls, d: dict, source: str = "") -> "Rule":
        for k in ("id", "title", "level", "detection"):
            if k not in d:
                raise RuleError(f"{source or d.get('id', '?')}: missing required key {k!r}")
        if d["level"] not in LEVELS:
            raise RuleError(f"{d['id']}: level must be one of {LEVELS}")
        det = dict(d["detection"])
        condition = det.pop("condition", None)
        if not condition:
            raise RuleError(f"{d['id']}: detection.condition is required")
        if not det:
            raise RuleError(f"{d['id']}: detection needs at least one selection")
        bad_tags = [t for t in d.get("tags", []) if t.lower().startswith("attack.t") and not _TECH.match(t)]
        if bad_tags:
            raise RuleError(f"{d['id']}: malformed ATT&CK tag(s) {bad_tags}")
        return cls(
            id=d["id"], title=d["title"], level=d["level"], condition=condition,
            selections={n: Selection(n, s) for n, s in det.items()},
            description=d.get("description", ""), tags=list(d.get("tags", [])),
            tests=d.get("tests", {}), source=source,
        )

    def self_test(self) -> list[str]:
        """Run embedded positive/negative samples; return failure messages."""
        fails = []
        for i, ev in enumerate(self.tests.get("should_match", [])):
            if not self.matches(ev):
                fails.append(f"{self.id}: should_match[{i}] did not match")
        for i, ev in enumerate(self.tests.get("should_not_match", [])):
            if self.matches(ev):
                fails.append(f"{self.id}: should_not_match[{i}] matched")
        if not self.tests.get("should_match"):
            fails.append(f"{self.id}: no should_match test case")
        return fails


def load_rule_file(path: str | Path) -> Rule:
    p = Path(path)
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        raise RuleError(f"{p}: invalid JSON: {e}") from e
    return Rule.from_dict(data, source=str(p))


def load_rules(directory: str | Path) -> list[Rule]:
    if not Path(directory).is_dir():
        raise RuleError(f"rules directory not found: {directory}")
    rules = [load_rule_file(p) for p in sorted(Path(directory).rglob("*.json"))]
    ids = [r.id for r in rules]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise RuleError(f"duplicate rule id(s): {sorted(dup)}")
    return rules


def read_events(path: str | Path) -> Iterator[dict]:
    with open(path) as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError as e:
                raise RuleError(f"{path}:{n}: invalid JSON event: {e}") from e
            if isinstance(ev, dict):
                yield ev
