"""Rule model and YAML loading/validation."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from . import condition as cond
from .matcher import MatcherError, Selection

LEVELS = ("informational", "low", "medium", "high", "critical")
TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    level: str
    tags: list[str]
    selections: dict[str, Selection]
    ast: Any
    description: str = ""
    logsource: dict = field(default_factory=dict)
    falsepositives: list[str] = field(default_factory=list)
    path: str = ""

    @property
    def techniques(self) -> list[str]:
        return sorted({m.group(1).upper() for t in self.tags if (m := TECHNIQUE.match(t))})

    @property
    def tactics(self) -> list[str]:
        return sorted(t[7:] for t in self.tags
                      if t.lower().startswith("attack.") and not TECHNIQUE.match(t))

    def matches(self, event: Mapping[str, Any]) -> bool:
        cache: dict[str, bool] = {}

        def lookup(name: str) -> bool:
            if name not in cache:
                cache[name] = self.selections[name].matches(event)
            return cache[name]
        return cond.evaluate(self.ast, lookup)


def parse_rule(doc: Mapping[str, Any], path: str = "") -> Rule:
    for key in ("title", "id", "detection", "level"):
        if key not in doc:
            raise RuleError(f"{path}: missing required field {key!r}")
    if doc["level"] not in LEVELS:
        raise RuleError(f"{path}: level must be one of {LEVELS}")
    det = dict(doc["detection"])
    condition = det.pop("condition", None)
    if not isinstance(condition, str):
        raise RuleError(f"{path}: detection.condition must be a string")
    if not det:
        raise RuleError(f"{path}: detection has no selections")
    try:
        selections = {name: Selection(spec) for name, spec in det.items()}
        ast = cond.parse(condition, set(selections))
    except (MatcherError, cond.ConditionError) as e:
        raise RuleError(f"{path}: {doc['id']}: {e}") from e
    return Rule(
        id=str(doc["id"]), title=doc["title"], level=doc["level"],
        tags=[str(t) for t in doc.get("tags", [])], selections=selections, ast=ast,
        description=doc.get("description", ""), logsource=doc.get("logsource", {}) or {},
        falsepositives=doc.get("falsepositives", []) or [], path=path,
    )


def load_rules(path: str | Path) -> list[Rule]:
    p = Path(path)
    files = sorted(p.rglob("*.y*ml")) if p.is_dir() else [p]
    rules, seen = [], set()
    for f in files:
        try:
            docs = [d for d in yaml.safe_load_all(f.read_text()) if d]
        except yaml.YAMLError as e:
            raise RuleError(f"{f}: invalid YAML: {e}") from e
        for d in docs:
            r = parse_rule(d, str(f))
            if r.id in seen:
                raise RuleError(f"{f}: duplicate rule id {r.id}")
            seen.add(r.id)
            rules.append(r)
    return rules
