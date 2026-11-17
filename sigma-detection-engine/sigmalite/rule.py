"""Load and validate Sigma rules from YAML into compiled :class:`Rule` objects."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .condition import ConditionError, Node, evaluate, parse_condition
from .matcher import MatcherError, Predicate, compile_selection

LEVELS = ("informational", "low", "medium", "high", "critical")
LEVEL_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}
_TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


class RuleError(ValueError):
    """A rule file is malformed. The message names the file and the problem."""


@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str = ""
    status: str = "experimental"
    tags: list[str] = field(default_factory=list)
    logsource: dict[str, str] = field(default_factory=dict)
    falsepositives: list[str] = field(default_factory=list)
    detection: dict[str, Any] = field(default_factory=dict)
    # Detection-as-code test cases embedded in the rule (sigmalite extension).
    tests: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    path: str | None = None
    _condition: Node | None = field(default=None, repr=False)
    _selections: dict[str, Predicate] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------ ATT&CK

    @property
    def techniques(self) -> list[str]:
        return [m.group(1).upper() for t in self.tags if (m := _TECHNIQUE_RE.match(t))]

    @property
    def tactics(self) -> list[str]:
        from .attack import TACTICS  # local import avoids a cycle

        return [t.split(".", 1)[1] for t in self.tags
                if t.lower().startswith("attack.") and t.split(".", 1)[1] in TACTICS]

    # ------------------------------------------------------------------ matching

    def compile(self, field_map: Mapping[str, str] | None = None) -> "Rule":
        det = dict(self.detection)
        condition = det.pop("condition", None)
        det.pop("timeframe", None)
        if condition is None:
            raise RuleError(f"{self._where()}: detection has no 'condition'")
        if not det:
            raise RuleError(f"{self._where()}: detection has no selections")
        try:
            self._selections = {name: compile_selection(sel, field_map) for name, sel in det.items()}
            self._condition = parse_condition(condition, list(det))
        except (MatcherError, ConditionError) as exc:
            raise RuleError(f"{self._where()}: {exc}") from exc
        return self

    def matches(self, event: Mapping[str, Any]) -> bool:
        if self._condition is None:
            self.compile()
        cache: dict[str, bool] = {}

        def resolve(name: str) -> bool:
            if name not in cache:
                cache[name] = self._selections[name](event)
            return cache[name]

        return evaluate(self._condition, resolve)  # type: ignore[arg-type]

    def applies_to(self, event_logsource: Mapping[str, Any] | None) -> bool:
        """True if this rule's logsource is compatible with the event's.

        Events without logsource metadata are evaluated by every rule; any
        logsource key both sides declare must agree (case-insensitive).
        """
        if not event_logsource:
            return True
        return all(
            str(event_logsource[k]).lower() == str(v).lower()
            for k, v in self.logsource.items()
            if k in ("product", "category", "service") and k in event_logsource
        )

    def _where(self) -> str:
        return self.path or self.title or self.id


def rule_from_dict(data: Mapping[str, Any], path: str | None = None) -> Rule:
    where = path or "<rule>"
    if not isinstance(data, Mapping):
        raise RuleError(f"{where}: rule must be a YAML mapping")
    missing = [k for k in ("title", "detection") if k not in data]
    if missing:
        raise RuleError(f"{where}: missing required field(s) {missing}")
    level = str(data.get("level", "medium")).lower()
    if level not in LEVEL_RANK:
        raise RuleError(f"{where}: invalid level {level!r}; expected one of {LEVELS}")
    if not isinstance(data["detection"], Mapping):
        raise RuleError(f"{where}: 'detection' must be a mapping")
    tests = data.get("tests") or {}
    if not isinstance(tests, Mapping) or set(tests) - {"match", "no_match"}:
        raise RuleError(f"{where}: 'tests' may only contain 'match' and 'no_match' lists")
    rule = Rule(
        id=str(data.get("id") or data["title"]),
        title=str(data["title"]),
        level=level,
        description=str(data.get("description", "")).strip(),
        status=str(data.get("status", "experimental")),
        tags=[str(t).lower() for t in data.get("tags", []) or []],
        logsource=dict(data.get("logsource", {}) or {}),
        falsepositives=[str(f) for f in data.get("falsepositives", []) or []],
        detection=dict(data["detection"]),
        tests={k: list(v or []) for k, v in tests.items()},
        path=path,
    )
    return rule


def load_rule(path: str | Path, field_map: Mapping[str, str] | None = None) -> Rule:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from exc
    return rule_from_dict(data, str(path)).compile(field_map)


def load_rules(source: str | Path, field_map: Mapping[str, str] | None = None) -> list[Rule]:
    """Load one rule file or every ``*.yml``/``*.yaml`` under a directory.

    Duplicate rule IDs are rejected: they make alert de-duplication and
    coverage reporting ambiguous.
    """
    source = Path(source)
    if not source.exists():
        raise RuleError(f"{source}: no such file or directory")
    files = [source] if source.is_file() else sorted(
        p for p in source.rglob("*") if p.suffix in (".yml", ".yaml")
    )
    if not files:
        raise RuleError(f"{source}: no .yml/.yaml rule files found")
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for f in files:
        rule = load_rule(f, field_map)
        if rule.id in seen:
            raise RuleError(f"{f}: duplicate rule id {rule.id!r} (also in {seen[rule.id]})")
        seen[rule.id] = str(f)
        rules.append(rule)
    return rules
