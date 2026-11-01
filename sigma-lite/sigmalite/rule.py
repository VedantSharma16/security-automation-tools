"""Rule model, loading and validation."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .condition import ConditionError, Node, parse

LEVELS = ("informational", "low", "medium", "high", "critical")
_TECH = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    title: str
    id: str
    level: str
    description: str
    tags: list[str]
    detection: dict[str, Any]
    condition: str
    ast: Node
    tests: dict[str, list[dict]] = field(default_factory=dict)
    path: str = ""

    @property
    def techniques(self) -> list[str]:
        return sorted({m.group(1).upper() for t in self.tags if (m := _TECH.match(t))})

    @property
    def tactics(self) -> list[str]:
        return sorted(t[7:] for t in self.tags
                      if t.startswith("attack.") and not _TECH.match(t))


def from_dict(doc: dict, path: str = "") -> Rule:
    if not isinstance(doc, dict):
        raise RuleError(f"{path}: rule must be a mapping")
    for key in ("title", "id", "detection"):
        if key not in doc:
            raise RuleError(f"{path}: missing required field '{key}'")
    level = str(doc.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"{path}: invalid level {level!r}")
    det = dict(doc["detection"])
    condition = det.pop("condition", None)
    if not isinstance(condition, str):
        raise RuleError(f"{path}: detection.condition must be a string")
    if not det:
        raise RuleError(f"{path}: detection has no selections")
    try:
        ast = parse(condition)
    except ConditionError as e:
        raise RuleError(f"{path}: bad condition: {e}") from e
    import fnmatch
    for name in ast.names():
        if "*" in name:
            if not any(fnmatch.fnmatchcase(s, name) for s in det):
                raise RuleError(f"{path}: pattern {name!r} matches no selection")
        elif name not in det:
            raise RuleError(f"{path}: condition references undefined selection {name!r}")
    tests = doc.get("tests") or {}
    return Rule(
        title=str(doc["title"]), id=str(doc["id"]), level=level,
        description=str(doc.get("description", "")), tags=list(doc.get("tags") or []),
        detection=det, condition=condition, ast=ast,
        tests={"match": list(tests.get("match") or []),
               "no_match": list(tests.get("no_match") or [])},
        path=path,
    )


def load_rules(location: str | Path) -> list[Rule]:
    """Load one rule file or every ``*.yml``/``*.yaml`` under a directory."""
    p = Path(location)
    files = sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")]) if p.is_dir() else [p]
    rules, seen = [], {}
    for f in files:
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise RuleError(f"{f}: invalid YAML: {e}") from e
        rule = from_dict(doc, str(f))
        if rule.id in seen:
            raise RuleError(f"{f}: duplicate rule id {rule.id} (also in {seen[rule.id]})")
        seen[rule.id] = str(f)
        rules.append(rule)
    return rules
