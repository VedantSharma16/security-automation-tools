"""Rule loading and validation (Sigma-style YAML)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .condition import ConditionError, evaluate, parse_condition
from .matcher import MatcherError, Selection

LEVELS = ["informational", "low", "medium", "high", "critical"]
ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|[a-z_]+)$")


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    title: str
    id: str
    level: str
    description: str
    tags: list[str]
    selections: dict[str, Selection]
    condition_ast: tuple
    condition: str
    source: str = ""
    falsepositives: list[str] = field(default_factory=list)

    @property
    def techniques(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags
                if re.match(r"^attack\.t\d{4}", t)]

    @property
    def tactics(self) -> list[str]:
        return [t.split(".", 1)[1] for t in self.tags
                if t.startswith("attack.") and not re.match(r"^attack\.t\d{4}", t)]

    def matches(self, event: dict) -> bool:
        cache: dict[str, bool] = {}

        def sel(name: str) -> bool:
            if name not in cache:
                cache[name] = self.selections[name].matches(event)
            return cache[name]

        return evaluate(self.condition_ast, sel)


def parse_rule(data: dict, source: str = "") -> Rule:
    if not isinstance(data, dict):
        raise RuleError(f"{source}: rule must be a mapping")
    for key in ("title", "detection"):
        if key not in data:
            raise RuleError(f"{source}: missing required key '{key}'")
    level = str(data.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"{source}: invalid level {level!r} (expected one of {LEVELS})")
    tags = [str(t).lower() for t in data.get("tags", [])]
    for t in tags:
        if t.startswith("attack.") and not ATTACK_TAG.match(t):
            raise RuleError(f"{source}: malformed ATT&CK tag {t!r}")

    detection = dict(data["detection"])
    condition = detection.pop("condition", None)
    if not isinstance(condition, str) or not detection:
        raise RuleError(f"{source}: detection needs selections and a string 'condition'")
    try:
        selections = {name: Selection(spec) for name, spec in detection.items()}
        ast = parse_condition(condition, list(selections))
    except (MatcherError, ConditionError) as exc:
        raise RuleError(f"{source}: {exc}") from exc

    return Rule(
        title=str(data["title"]), id=str(data.get("id", data["title"])), level=level,
        description=str(data.get("description", "")), tags=tags, selections=selections,
        condition_ast=ast, condition=condition, source=source,
        falsepositives=[str(f) for f in data.get("falsepositives", [])],
    )


def load_rules(path: str | Path) -> list[Rule]:
    """Load one rule file or every ``*.yml``/``*.yaml`` file under a directory."""
    p = Path(path)
    files = sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")]) if p.is_dir() else [p]
    if not files:
        raise RuleError(f"no rule files found in {p}")
    rules: list[Rule] = []
    for f in files:
        try:
            docs = list(yaml.safe_load_all(f.read_text(encoding="utf-8")))
        except yaml.YAMLError as exc:
            raise RuleError(f"{f}: invalid YAML: {exc}") from exc
        rules.extend(parse_rule(d, str(f)) for d in docs if d)
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"duplicate rule ids: {sorted(dupes)}")
    return rules
