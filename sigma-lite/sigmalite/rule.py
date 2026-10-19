"""Rule model, loading and validation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

from .condition import ConditionError, compile_condition
from .matcher import MatcherError, build_field_matcher, get_field

LEVELS = ("informational", "low", "medium", "high", "critical")
_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    level: str
    tags: list[str]
    logsource: dict
    condition: str
    description: str = ""
    path: str = ""
    _selections: dict[str, Callable[[dict], bool]] = field(default_factory=dict, repr=False)
    _eval: Callable[[dict[str, bool]], bool] = field(default=lambda r: False, repr=False)

    @property
    def techniques(self) -> list[str]:
        return [m.group(1).upper() for t in self.tags if (m := _TECHNIQUE.match(t))]

    @property
    def tactics(self) -> list[str]:
        return [t[7:] for t in self.tags if t.startswith("attack.") and not _TECHNIQUE.match(t)]

    def applies_to(self, event: dict) -> bool:
        return all(
            str(get_field(event, k) or "").lower() == str(v).lower()
            for k, v in self.logsource.items()
        )

    def matches(self, event: dict) -> bool:
        if not self.applies_to(event):
            return False
        return self._eval({name: sel(event) for name, sel in self._selections.items()})


def _build_selection(name: str, body) -> Callable[[dict], bool]:
    # A selection is a map (AND across fields) or a list of maps (OR across maps).
    maps = body if isinstance(body, list) else [body]
    matchers = []
    for m in maps:
        if not isinstance(m, dict) or not m:
            raise RuleError(f"selection {name!r} must be a non-empty map or list of maps")
        matchers.append([build_field_matcher(k, v) for k, v in m.items()])
    return lambda event: any(all(f(event) for f in group) for group in matchers)


def parse_rule(data: dict, path: str = "") -> Rule:
    if not isinstance(data, dict):
        raise RuleError("rule must be a YAML mapping")
    for key in ("title", "id", "detection"):
        if key not in data:
            raise RuleError(f"missing required field {key!r}")
    level = str(data.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"invalid level {level!r}; expected one of {LEVELS}")
    detection = dict(data["detection"])
    condition = detection.pop("condition", None)
    if not condition or not detection:
        raise RuleError("detection needs a condition and at least one selection")
    try:
        selections = {n: _build_selection(n, b) for n, b in detection.items()}
        evaluator = compile_condition(str(condition), list(selections))
    except (MatcherError, ConditionError) as exc:
        raise RuleError(str(exc)) from exc
    return Rule(
        id=str(data["id"]),
        title=str(data["title"]),
        level=level,
        tags=[str(t) for t in data.get("tags", [])],
        logsource=dict(data.get("logsource") or {}),
        condition=str(condition),
        description=str(data.get("description", "")).strip(),
        path=path,
        _selections=selections,
        _eval=evaluator,
    )


def load_rules(location: str | Path) -> list[Rule]:
    """Load every ``*.yml``/``*.yaml`` rule under a directory (or a single file)."""
    loc = Path(location)
    files = [loc] if loc.is_file() else sorted([*loc.rglob("*.yml"), *loc.rglob("*.yaml")])
    rules, seen = [], {}
    for f in files:
        try:
            rule = parse_rule(yaml.safe_load(f.read_text(encoding="utf-8")), str(f))
        except (yaml.YAMLError, RuleError) as exc:
            raise RuleError(f"{f}: {exc}") from exc
        if rule.id in seen:
            raise RuleError(f"{f}: duplicate rule id {rule.id!r} (also in {seen[rule.id]})")
        seen[rule.id] = f
        rules.append(rule)
    return rules
