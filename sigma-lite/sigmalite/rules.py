"""Load and validate Sigma rules from YAML."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from .condition import (
    ConditionError,
    Node,
    evaluate_condition,
    parse_condition,
    referenced_names,
)
from .matchers import ModifierError, build_field_matcher

LEVELS = ("informational", "low", "medium", "high", "critical")


class RuleError(ValueError):
    """Raised when a rule file is invalid."""


def _compile_selection(name: str, body: Any) -> Callable[[dict], bool]:
    """A map is AND of its fields; a list of maps is OR; a list of strings is a keyword search."""
    if isinstance(body, dict):
        matchers = [build_field_matcher(k, v) for k, v in body.items()]
        if not matchers:
            raise RuleError(f"selection {name!r} is empty")
        return lambda ev: all(m(ev) for m in matchers)
    if isinstance(body, list):
        if body and all(isinstance(i, dict) for i in body):
            subs = [_compile_selection(name, i) for i in body]
            return lambda ev: any(s(ev) for s in subs)
        if body and all(isinstance(i, (str, int, float)) for i in body):
            needles = [str(i).lower() for i in body]
            return lambda ev: any(n in str(v).lower() for v in ev.values() for n in needles)
    raise RuleError(f"selection {name!r} must be a map, a list of maps, or a list of keywords")


@dataclass
class Rule:
    id: str
    title: str
    level: str
    tags: list[str]
    description: str
    condition: Node
    selections: dict[str, Callable[[dict], bool]] = field(repr=False)
    logsource: dict = field(default_factory=dict)
    source: str = ""

    @property
    def attack_techniques(self) -> list[str]:
        """MITRE ATT&CK technique IDs from ``attack.tNNNN`` tags."""
        return [
            t.split(".", 1)[1].upper()
            for t in self.tags
            if t.lower().startswith("attack.t") and t.split(".", 1)[1][1:2].isdigit()
        ]

    def matches(self, event: dict) -> bool:
        thunks = {n: (lambda f=f: f(event)) for n, f in self.selections.items()}
        return evaluate_condition(self.condition, thunks)


def rule_from_dict(data: dict, source: str = "") -> Rule:
    if not isinstance(data, dict):
        raise RuleError(f"{source}: rule must be a YAML mapping")
    for key in ("title", "detection"):
        if key not in data:
            raise RuleError(f"{source}: missing required key {key!r}")
    detection = data["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleError(f"{source}: detection must contain a 'condition'")
    level = str(data.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"{source}: invalid level {level!r}; expected one of {LEVELS}")

    try:
        selections = {
            n: _compile_selection(n, b) for n, b in detection.items() if n != "condition"
        }
        raw_condition = detection["condition"]
        if isinstance(raw_condition, list):  # multiple conditions are OR-ed
            raw_condition = " or ".join(f"({c})" for c in raw_condition)
        condition = parse_condition(str(raw_condition))
        for name in referenced_names(condition):
            if "*" not in name and name != "them" and name not in selections:
                raise RuleError(f"{source}: condition references unknown selection {name!r}")
    except (ConditionError, ModifierError, ValueError) as exc:
        if isinstance(exc, RuleError):
            raise
        raise RuleError(f"{source}: {exc}") from exc

    return Rule(
        id=str(data.get("id", data["title"])),
        title=str(data["title"]),
        level=level,
        tags=[str(t) for t in data.get("tags", [])],
        description=str(data.get("description", "")).strip(),
        condition=condition,
        selections=selections,
        logsource=data.get("logsource", {}) or {},
        source=source,
    )


def load_rule(path: str | Path) -> Rule:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from exc
    return rule_from_dict(data, source=str(path))


def load_rules(path: str | Path) -> list[Rule]:
    """Load one rule file, or every ``*.yml``/``*.yaml`` under a directory."""
    path = Path(path)
    if path.is_file():
        return [load_rule(path)]
    files = sorted([*path.rglob("*.yml"), *path.rglob("*.yaml")])
    if not files:
        raise RuleError(f"no rule files found under {path}")
    return [load_rule(f) for f in files]
