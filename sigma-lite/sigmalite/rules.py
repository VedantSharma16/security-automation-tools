"""Rule model, loading and validation. Rules are JSON documents in Sigma layout."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .condition import ConditionError, compile_condition
from .matcher import MODIFIERS, Selection

LEVELS = ("informational", "low", "medium", "high", "critical")


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    level: str
    tags: list[str]
    selections: dict[str, Selection]
    condition_text: str
    description: str = ""
    _check: object = field(default=None, repr=False)

    @property
    def attack_techniques(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if t.startswith("attack.t")]

    def matches(self, event: dict) -> bool:
        return self._check({n: s.matches(event) for n, s in self.selections.items()})


def parse_rule(doc: dict, source: str = "<rule>") -> Rule:
    try:
        det = doc["detection"]
        cond = det["condition"]
        title = doc["title"]
        rid = doc.get("id") or title
    except (KeyError, TypeError) as exc:
        raise RuleError(f"{source}: missing required field {exc}") from None
    level = doc.get("level", "medium")
    if level not in LEVELS:
        raise RuleError(f"{source}: invalid level {level!r}")
    sels = {}
    for name, body in det.items():
        if name == "condition":
            continue
        try:
            sels[name] = Selection.from_spec(body)
        except ValueError as exc:
            raise RuleError(f"{source}: selection {name!r}: {exc}") from None
    if not sels:
        raise RuleError(f"{source}: no selections defined")
    try:
        check = compile_condition(cond, list(sels))
    except ConditionError as exc:
        raise RuleError(f"{source}: {exc}") from None
    return Rule(rid, title, level, list(doc.get("tags", [])), sels, cond,
                doc.get("description", ""), check)


def load_rules(path: str | Path) -> list[Rule]:
    """Load one rule file or every ``*.json`` rule under a directory."""
    p = Path(path)
    files = sorted(p.rglob("*.json")) if p.is_dir() else [p]
    rules = []
    for f in files:
        try:
            doc = json.loads(f.read_text())
        except json.JSONDecodeError as exc:
            raise RuleError(f"{f}: invalid JSON: {exc}") from None
        for d in doc if isinstance(doc, list) else [doc]:
            rules.append(parse_rule(d, str(f)))
    return rules


__all__ = ["Rule", "RuleError", "parse_rule", "load_rules", "MODIFIERS"]
