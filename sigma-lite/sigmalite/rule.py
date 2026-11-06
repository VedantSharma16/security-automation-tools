"""Rule loading and validation."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from .condition import Condition, compile_condition
from .matcher import RuleError, compile_field_matcher

LEVELS = ("informational", "low", "medium", "high", "critical")
_ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
_TACTIC_TAG = re.compile(r"^attack\.([a-z_]+)$")


@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str
    condition: Condition
    selections: dict[str, Callable[[dict], bool]]
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    source: str = ""

    @property
    def techniques(self) -> list[str]:
        return sorted({m.group(1).upper() for t in self.tags if (m := _ATTACK_TAG.match(t))})

    @property
    def tactics(self) -> list[str]:
        return sorted({m.group(1) for t in self.tags
                       if (m := _TACTIC_TAG.match(t)) and not _ATTACK_TAG.match(t)})

    def matches(self, event: dict) -> bool:
        results = {n: fn(event) for n, fn in self.selections.items()}
        return self.condition.evaluate(results)


def _compile_selection(name: str, body: Any) -> Callable[[dict], bool]:
    if isinstance(body, dict):  # AND across fields
        if not body:
            raise RuleError(f"selection {name!r} is empty")
        preds = [compile_field_matcher(k, v) for k, v in body.items()]
        return lambda ev: all(p(ev) for p in preds)
    if isinstance(body, list) and body and all(isinstance(b, dict) for b in body):  # OR of maps
        subs = [_compile_selection(name, b) for b in body]
        return lambda ev: any(s(ev) for s in subs)
    raise RuleError(f"selection {name!r} must be a mapping or a list of mappings")


def parse_rule(data: dict, source: str = "") -> Rule:
    if not isinstance(data, dict):
        raise RuleError("rule must be a YAML mapping")
    for key in ("title", "id", "detection"):
        if key not in data:
            raise RuleError(f"missing required field {key!r}")
    level = str(data.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"invalid level {level!r}; expected one of {LEVELS}")
    det = dict(data["detection"])
    cond_text = det.pop("condition", None)
    if not cond_text:
        raise RuleError("detection.condition is required")
    if isinstance(cond_text, list):  # Sigma allows a list meaning OR
        cond_text = " or ".join(f"({c})" for c in cond_text)
    if not det:
        raise RuleError("detection has no selections")
    selections = {str(n): _compile_selection(str(n), b) for n, b in det.items()}
    condition = compile_condition(str(cond_text), list(selections))
    unused = set(selections) - condition.references
    if unused:
        raise RuleError(f"unused selection(s): {', '.join(sorted(unused))}")
    return Rule(
        id=str(data["id"]), title=str(data["title"]), level=level,
        description=str(data.get("description", "")).strip(),
        condition=condition, selections=selections,
        tags=[str(t) for t in data.get("tags", [])],
        falsepositives=[str(f) for f in data.get("falsepositives", [])],
        source=source,
    )


def load_rules(path: str | Path) -> tuple[list[Rule], list[tuple[str, str]]]:
    """Load every ``*.yml``/``*.yaml`` under *path*. Returns (rules, [(file, error)])."""
    p = Path(path)
    files = [p] if p.is_file() else sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")])
    rules, errors, seen = [], [], {}
    for f in files:
        try:
            for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
                if doc is None:
                    continue
                rule = parse_rule(doc, str(f))
                if rule.id in seen:
                    raise RuleError(f"duplicate rule id {rule.id} (also in {seen[rule.id]})")
                seen[rule.id] = str(f)
                rules.append(rule)
        except (RuleError, yaml.YAMLError) as exc:
            errors.append((str(f), str(exc).splitlines()[0]))
    return rules, errors
