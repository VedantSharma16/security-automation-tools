"""Load Sigma rules from YAML and compile them."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .condition import ConditionError, Evaluator, parse_condition
from .matchers import ModifierError, Selection

LEVELS = ["informational", "low", "medium", "high", "critical"]
_SKIP_KEYS = {"condition", "timeframe"}


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    level: str
    tags: list[str]
    selections: dict[str, Selection]
    condition: Evaluator
    description: str = ""
    source: str = ""
    falsepositives: list[str] = field(default_factory=list)

    @property
    def techniques(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags
                if t.lower().startswith("attack.t")]

    @property
    def tactics(self) -> list[str]:
        return [t.split(".", 1)[1] for t in self.tags
                if t.lower().startswith("attack.") and not t.lower().startswith("attack.t1")
                and not t.lower().startswith("attack.s")]

    def evaluate(self, event: dict) -> bool:
        return self.condition({n: s.matches(event) for n, s in self.selections.items()})


def compile_rule(doc: dict, source: str = "") -> Rule:
    if not isinstance(doc, dict):
        raise RuleError(f"{source}: rule must be a mapping")
    title = doc.get("title")
    det = doc.get("detection")
    if not title or not isinstance(det, dict) or "condition" not in det:
        raise RuleError(f"{source}: needs 'title' and 'detection' with 'condition'")
    level = str(doc.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"{source}: invalid level {level!r}")
    try:
        sels = {n: Selection(s) for n, s in det.items() if n not in _SKIP_KEYS}
        cond = det["condition"]
        if isinstance(cond, list):  # multiple conditions are OR'd
            cond = " or ".join(f"({c})" for c in cond)
        evaluator = parse_condition(str(cond), set(sels))
    except (ModifierError, ConditionError) as e:
        raise RuleError(f"{source}: {title}: {e}") from e
    fps = doc.get("falsepositives") or []
    return Rule(id=str(doc.get("id", title)), title=str(title), level=level,
                tags=[str(t) for t in doc.get("tags") or []], selections=sels,
                condition=evaluator, description=str(doc.get("description", "")),
                source=source, falsepositives=fps if isinstance(fps, list) else [str(fps)])


def load_rules(path: str | Path) -> list[Rule]:
    """Load one rule file or every ``*.yml``/``*.yaml`` under a directory."""
    p = Path(path)
    files = sorted(f for f in p.rglob("*") if f.suffix in (".yml", ".yaml")) if p.is_dir() else [p]
    if not files:
        raise RuleError(f"no rule files found in {p}")
    rules: list[Rule] = []
    for f in files:
        try:
            docs: list[Any] = list(yaml.safe_load_all(f.read_text(encoding="utf-8")))
        except (yaml.YAMLError, OSError) as e:
            raise RuleError(f"{f}: {e}") from e
        rules.extend(compile_rule(d, str(f)) for d in docs if d)
    return rules
