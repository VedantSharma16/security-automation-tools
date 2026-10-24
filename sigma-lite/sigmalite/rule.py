"""Rule model and YAML loader."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from .condition import ConditionError, compile_condition
from .matchers import MatcherError, build_field_matcher

LEVELS = ("informational", "low", "medium", "high", "critical")
TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str
    tags: list[str]
    selections: dict[str, Callable[[dict], bool]]
    condition_text: str
    evaluate: Callable[[dict[str, bool]], bool]
    tests: dict[str, list[dict]] = field(default_factory=dict)
    path: str = ""

    @property
    def techniques(self) -> list[str]:
        return [m.group(1).upper() for t in self.tags if (m := TECHNIQUE.match(t))]

    def matches(self, event: dict) -> bool:
        return self.evaluate({n: p(event) for n, p in self.selections.items()})


def _build_selection(name: str, spec: Any) -> Callable[[dict], bool]:
    # A selection is a map (AND of fields) or a list of maps (OR of maps).
    maps = spec if isinstance(spec, list) else [spec]
    if not maps or not all(isinstance(m, dict) and m for m in maps):
        raise RuleError(f"selection {name!r} must be a non-empty map or list of maps")
    compiled = []
    for m in maps:
        compiled.append([build_field_matcher(k, v)[1] for k, v in m.items()])
    return lambda e: any(all(p(e) for p in preds) for preds in compiled)


def parse_rule(data: dict, path: str = "") -> Rule:
    if not isinstance(data, dict):
        raise RuleError(f"{path}: rule must be a mapping")
    for key in ("title", "id", "detection"):
        if key not in data:
            raise RuleError(f"{path}: missing required key {key!r}")
    level = str(data.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"{path}: invalid level {level!r}")
    det = dict(data["detection"])
    cond_text = det.pop("condition", None)
    if not cond_text or not det:
        raise RuleError(f"{path}: detection needs selections and a condition")
    try:
        selections = {n: _build_selection(n, s) for n, s in det.items()}
        evaluate = compile_condition(str(cond_text), list(selections))
    except (MatcherError, ConditionError, RuleError) as exc:
        raise RuleError(f"{path}: {exc}") from exc
    return Rule(
        id=str(data["id"]), title=data["title"], level=level,
        description=data.get("description", ""), tags=list(data.get("tags", [])),
        selections=selections, condition_text=str(cond_text), evaluate=evaluate,
        tests=data.get("tests", {}) or {}, path=path,
    )


def load_rule(path: str | Path) -> Rule:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from exc
    return parse_rule(data, str(path))


def load_rules(directory: str | Path) -> list[Rule]:
    files = sorted(Path(directory).rglob("*.y*ml"))
    rules = [load_rule(f) for f in files]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"duplicate rule ids: {sorted(dupes)}")
    return rules
