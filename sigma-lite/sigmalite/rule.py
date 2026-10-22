"""Sigma rule loading and validation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .condition import (ConditionError, evaluate, parse_condition,
                        referenced_names)
from .matchers import FieldMatcher, KeywordMatcher, MatcherError

LEVELS = ("informational", "low", "medium", "high", "critical")
TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
TACTIC_PREFIX = "attack."


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str
    tags: list[str]
    logsource: dict
    selections: dict[str, list]  # name -> list of alternative matcher-groups (OR of ANDs)
    condition_ast: Any
    condition_text: str
    falsepositives: list[str] = field(default_factory=list)
    path: str = ""

    @property
    def techniques(self) -> list[str]:
        return sorted({m.group(1).upper() for t in self.tags if (m := TECHNIQUE_RE.match(t))})

    @property
    def tactics(self) -> list[str]:
        return sorted({t[len(TACTIC_PREFIX):] for t in self.tags
                       if t.lower().startswith(TACTIC_PREFIX) and not TECHNIQUE_RE.match(t)})

    def matches(self, event: dict) -> bool:
        cache: dict[str, bool] = {}

        def sel(name: str) -> bool:
            if name not in cache:
                cache[name] = any(all(m.matches(event) for m in group)
                                  for group in self.selections[name])
            return cache[name]

        return evaluate(self.condition_ast, list(self.selections), sel)


def _compile_selection(name: str, body: Any) -> list[list]:
    """Return a list of alternatives; each alternative is a list of matchers (AND)."""
    if isinstance(body, dict):
        alternatives = [body]
    elif isinstance(body, list) and body and all(isinstance(x, dict) for x in body):
        alternatives = body
    elif isinstance(body, list) and body:
        return [[KeywordMatcher(body)]]
    else:
        raise RuleError(f"selection {name!r} must be a mapping, list of mappings, or keyword list")
    compiled = []
    for alt in alternatives:
        if not alt:
            raise RuleError(f"selection {name!r} contains an empty mapping")
        try:
            compiled.append([FieldMatcher(k, v) for k, v in alt.items()])
        except MatcherError as exc:
            raise RuleError(f"selection {name!r}: {exc}") from exc
    return compiled


def parse_rule(doc: dict, path: str = "") -> Rule:
    if not isinstance(doc, dict):
        raise RuleError("rule document must be a mapping")
    for key in ("title", "detection"):
        if key not in doc:
            raise RuleError(f"missing required key {key!r}")
    level = str(doc.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"invalid level {level!r}; expected one of {LEVELS}")
    detection = doc["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleError("detection must be a mapping containing 'condition'")
    cond_text = detection["condition"]
    if isinstance(cond_text, list):
        cond_text = " or ".join(f"({c})" for c in cond_text)
    selections = {k: _compile_selection(k, v) for k, v in detection.items()
                  if k not in ("condition", "timeframe")}
    if not selections:
        raise RuleError("detection has no selections")
    try:
        ast = parse_condition(str(cond_text))
    except ConditionError as exc:
        raise RuleError(f"bad condition {cond_text!r}: {exc}") from exc
    missing = referenced_names(ast) - set(selections)
    if missing:
        raise RuleError(f"condition references undefined selection(s): {sorted(missing)}")
    return Rule(
        id=str(doc.get("id", doc["title"])), title=str(doc["title"]), level=level,
        description=str(doc.get("description", "")).strip(),
        tags=[str(t) for t in doc.get("tags", [])],
        logsource=doc.get("logsource") or {}, selections=selections,
        condition_ast=ast, condition_text=str(cond_text),
        falsepositives=[str(x) for x in doc.get("falsepositives", [])], path=path,
    )


def load_rule(path: str | Path) -> Rule:
    path = Path(path)
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from exc
    try:
        return parse_rule(doc, str(path))
    except RuleError as exc:
        raise RuleError(f"{path}: {exc}") from exc


def load_rules(directory: str | Path) -> list[Rule]:
    directory = Path(directory)
    if directory.is_file():
        return [load_rule(directory)]
    files = sorted([*directory.rglob("*.yml"), *directory.rglob("*.yaml")])
    if not files:
        raise RuleError(f"no rule files found in {directory}")
    return [load_rule(f) for f in files]
