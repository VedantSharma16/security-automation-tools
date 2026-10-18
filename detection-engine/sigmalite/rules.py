"""Rule model and loader.

Rules are JSON documents following the Sigma structure (``detection`` with
named selections plus a ``condition``) so they stay dependency-free::

    {"title": "...", "id": "...", "level": "high", "tags": ["attack.t1059.001"],
     "detection": {"sel": {"Image|endswith": "\\\\powershell.exe",
                           "CommandLine|contains": ["-enc", "-EncodedCommand"]},
                   "condition": "sel"}}

Field modifiers: ``contains``, ``startswith``, ``endswith``, ``re`` and the
default exact match (all case-insensitive except ``re``), plus ``all`` (list
values must all match instead of any). Within a selection mapping, fields are
AND-ed; list values are OR-ed. A selection may also be a list of mappings,
which are OR-ed. A ``null`` value matches a missing field.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .condition import ConditionError, compile_condition

LEVELS = ("informational", "low", "medium", "high", "critical")
MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}
_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


class RuleError(ValueError):
    pass


def _get(event: dict, path: str) -> Any:
    """Case-insensitive field lookup with dotted-path support."""
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        if part in cur:
            cur = cur[part]
        else:
            lowered = {k.lower(): v for k, v in cur.items()}
            if part.lower() not in lowered:
                return None
            cur = lowered[part.lower()]
    return cur


@dataclass(frozen=True)
class _Matcher:
    field: str
    op: str
    values: tuple
    require_all: bool = False

    def _one(self, actual: str, expected) -> bool:
        if self.op == "re":
            return expected.search(actual) is not None
        a, e = actual.lower(), str(expected).lower()
        if self.op == "contains":
            return e in a
        if self.op == "startswith":
            return a.startswith(e)
        if self.op == "endswith":
            return a.endswith(e)
        return a == e

    def matches(self, event: dict) -> bool:
        actual = _get(event, self.field)
        if actual is None:
            return any(v is None for v in self.values)
        checks = (self._one(str(actual), v) for v in self.values if v is not None)
        return all(checks) if self.require_all else any(checks)


def _compile_mapping(name: str, mapping: dict) -> list[_Matcher]:
    out = []
    for key, raw in mapping.items():
        field_name, *mods = key.split("|")
        bad = [m for m in mods if m not in MODIFIERS]
        if bad or not field_name:
            raise RuleError(f"selection {name!r}: invalid field spec {key!r}")
        ops = [m for m in mods if m != "all"]
        if len(ops) > 1:
            raise RuleError(f"selection {name!r}: multiple operators in {key!r}")
        op = ops[0] if ops else "equals"
        values = raw if isinstance(raw, list) else [raw]
        if not values:
            raise RuleError(f"selection {name!r}: {key!r} has no values")
        if op == "re":
            try:
                values = [re.compile(v) for v in values]
            except re.error as exc:
                raise RuleError(f"selection {name!r}: bad regex in {key!r}: {exc}") from exc
        out.append(_Matcher(field_name, op, tuple(values), "all" in mods))
    return out


@dataclass
class Rule:
    id: str
    title: str
    level: str
    tags: list[str]
    description: str
    selections: dict[str, list[list[_Matcher]]]
    condition_text: str
    _cond: Any = field(repr=False, default=None)
    source: str = ""

    @property
    def techniques(self) -> list[str]:
        return sorted({m.group(1).upper() for t in self.tags if (m := _TECHNIQUE.match(t))})

    @property
    def tactics(self) -> list[str]:
        return sorted(t[7:] for t in self.tags
                      if t.startswith("attack.") and not _TECHNIQUE.match(t))

    def matches(self, event: dict) -> bool:
        results = {
            name: any(all(m.matches(event) for m in group) for group in groups)
            for name, groups in self.selections.items()
        }
        return self._cond(results)


def parse_rule(doc: dict, source: str = "") -> Rule:
    for key in ("title", "id", "detection"):
        if key not in doc:
            raise RuleError(f"{source or 'rule'}: missing required key {key!r}")
    level = str(doc.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"{doc['id']}: level must be one of {LEVELS}, got {level!r}")
    detection = dict(doc["detection"])
    cond_text = detection.pop("condition", None)
    if not cond_text:
        raise RuleError(f"{doc['id']}: detection.condition is required")
    if not detection:
        raise RuleError(f"{doc['id']}: detection has no selections")
    selections = {}
    for name, body in detection.items():
        bodies = body if isinstance(body, list) else [body]
        if not all(isinstance(b, dict) and b for b in bodies):
            raise RuleError(f"{doc['id']}: selection {name!r} must be a mapping or list of mappings")
        selections[name] = [_compile_mapping(name, b) for b in bodies]
    try:
        cond, used = compile_condition(cond_text, list(selections))
    except ConditionError as exc:
        raise RuleError(f"{doc['id']}: {exc}") from exc
    unused = set(selections) - used
    if unused:
        raise RuleError(f"{doc['id']}: selections never referenced by condition: {sorted(unused)}")
    return Rule(doc["id"], doc["title"], level, list(doc.get("tags", [])),
                doc.get("description", ""), selections, cond_text, cond, source)


def load_rule_file(path: str | Path) -> Rule:
    path = Path(path)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuleError(f"{path}: invalid JSON: {exc}") from exc
    return parse_rule(doc, str(path))


def load_rules(path: str | Path) -> list[Rule]:
    """Load one rule file or every ``*.json`` rule under a directory."""
    path = Path(path)
    files = [path] if path.is_file() else sorted(path.rglob("*.json"))
    if not files:
        raise RuleError(f"no rule files found at {path}")
    rules = [load_rule_file(f) for f in files]
    seen: dict[str, str] = {}
    for r in rules:
        if r.id in seen:
            raise RuleError(f"duplicate rule id {r.id!r} in {r.source} and {seen[r.id]}")
        seen[r.id] = r.source
    return rules
