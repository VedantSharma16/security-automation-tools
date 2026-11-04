"""Rule loading, validation, and compilation."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

from .condition import ConditionError, parse_condition
from .matcher import ModifierError, compile_selection

LEVELS = ("informational", "low", "medium", "high", "critical")
_ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


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
    path: str
    selections: dict[str, Callable[[dict], bool]] = field(repr=False)
    condition_text: str = ""
    ast: tuple = field(default=(), repr=False)

    @property
    def techniques(self) -> list[str]:
        return sorted({m.group(1).upper() for t in self.tags if (m := _ATTACK_TAG.match(t))})

    @property
    def tactics(self) -> list[str]:
        return sorted({t[7:] for t in self.tags
                       if t.lower().startswith("attack.") and not _ATTACK_TAG.match(t)})


def parse_rule(doc: dict, path: str = "<memory>") -> Rule:
    if not isinstance(doc, dict):
        raise RuleError(f"{path}: rule must be a YAML mapping")
    for req in ("title", "detection"):
        if req not in doc:
            raise RuleError(f"{path}: missing required field '{req}'")
    level = str(doc.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"{path}: invalid level {level!r} (expected one of {LEVELS})")
    detection = doc["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleError(f"{path}: detection requires a 'condition'")
    sel_defs = {k: v for k, v in detection.items() if k != "condition"}
    if not sel_defs:
        raise RuleError(f"{path}: detection has no selections")
    try:
        selections = {name: compile_selection(v) for name, v in sel_defs.items()}
        cond = detection["condition"]
        if isinstance(cond, list):  # multiple conditions are OR'd
            cond = " or ".join(f"({c})" for c in cond)
        ast = parse_condition(str(cond), list(selections))
    except (ModifierError, ConditionError) as exc:
        raise RuleError(f"{path}: {exc}") from exc
    return Rule(
        id=str(doc.get("id", Path(path).stem)), title=str(doc["title"]), level=level,
        description=str(doc.get("description", "")), tags=[str(t) for t in doc.get("tags", [])],
        logsource=doc.get("logsource", {}) or {}, path=path, selections=selections,
        condition_text=str(cond), ast=ast,
    )


def load_rules(location: str | Path) -> list[Rule]:
    """Load one rule file or every ``*.yml``/``*.yaml`` under a directory (multi-doc supported)."""
    p = Path(location)
    files = [p] if p.is_file() else sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")])
    if not files:
        raise RuleError(f"no rule files found at {location}")
    rules: list[Rule] = []
    for f in files:
        try:
            docs = [d for d in yaml.safe_load_all(f.read_text(encoding="utf-8")) if d is not None]
        except yaml.YAMLError as exc:
            raise RuleError(f"{f}: invalid YAML: {exc}") from exc
        rules.extend(parse_rule(d, str(f)) for d in docs)
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"duplicate rule ids: {sorted(dupes)}")
    return rules
