"""Rule model and YAML loading/validation."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from .condition import ConditionError, compile_condition
from .matchers import match_selection

LEVELS = ("informational", "low", "medium", "high", "critical")
_TECHNIQUE = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.I)
_TACTIC = re.compile(r"^attack\.([a-z][a-z-]+)$")


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    level: str
    selections: dict[str, Any]
    condition_text: str
    tags: list[str] = field(default_factory=list)
    description: str = ""
    falsepositives: list[str] = field(default_factory=list)
    source: str = ""
    _cond: Callable[[dict[str, bool]], bool] = field(default=None, repr=False, compare=False)

    @property
    def techniques(self) -> list[str]:
        return sorted({f"T{m.group(1)}" for t in self.tags if (m := _TECHNIQUE.match(t))})

    @property
    def tactics(self) -> list[str]:
        return sorted({m.group(1) for t in self.tags
                       if (m := _TACTIC.match(t)) and not _TECHNIQUE.match(t)})

    def selection_results(self, event: dict) -> dict[str, bool]:
        return {n: match_selection(event, s) for n, s in self.selections.items()}

    def matches(self, event: dict) -> bool:
        return self._cond(self.selection_results(event))


def parse_rule(data: dict, source: str = "") -> Rule:
    where = f" ({source})" if source else ""
    if not isinstance(data, dict):
        raise RuleError(f"rule must be a mapping{where}")
    for key in ("title", "detection"):
        if key not in data:
            raise RuleError(f"missing required field {key!r}{where}")
    detection = data["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleError(f"detection needs a 'condition'{where}")
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        raise RuleError(f"detection defines no selections{where}")
    level = str(data.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"invalid level {level!r}, expected one of {LEVELS}{where}")
    condition = detection["condition"]
    if isinstance(condition, list):  # Sigma allows a list of conditions (OR)
        condition = " or ".join(f"({c})" for c in condition)
    try:
        cond = compile_condition(str(condition), list(selections))
    except ConditionError as e:
        raise RuleError(f"bad condition: {e}{where}") from e
    rule = Rule(
        id=str(data.get("id", data["title"])), title=str(data["title"]), level=level,
        selections=selections, condition_text=str(condition),
        tags=[str(t).lower() for t in data.get("tags", [])],
        description=str(data.get("description", "")),
        falsepositives=[str(x) for x in data.get("falsepositives", [])],
        source=source,
    )
    rule._cond = cond
    return rule


def load_rules(path: str | Path) -> list[Rule]:
    """Load rules from a .yml/.yaml file or recursively from a directory."""
    p = Path(path)
    files = sorted(p.rglob("*.y*ml")) if p.is_dir() else [p]
    rules = []
    for f in files:
        try:
            docs = list(yaml.safe_load_all(f.read_text(encoding="utf-8")))
        except yaml.YAMLError as e:
            raise RuleError(f"invalid YAML in {f}: {e}") from e
        rules += [parse_rule(d, str(f)) for d in docs if d]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"duplicate rule id(s): {sorted(dupes)}")
    return rules
