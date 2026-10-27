"""Rule model and loader. Rules are JSON documents (no third-party deps)."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import condition as cond
from .matchers import FieldMatcher, MatcherError

LEVELS = ["informational", "low", "medium", "high", "critical"]
_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    level: str
    condition_text: str
    selections: dict[str, list[FieldMatcher]]
    tags: list[str] = field(default_factory=list)
    description: str = ""
    source: str = ""
    _ast: cond.Node | None = None

    @property
    def techniques(self) -> list[str]:
        return sorted({m.group(1).upper() for t in self.tags if (m := _TECHNIQUE.match(t))})

    def evaluate(self, event: dict) -> bool:
        # A selection is an AND of its field matchers.
        results = {n: all(m.matches(event) for m in ms) for n, ms in self.selections.items()}
        return cond.evaluate(self._ast, results)


def parse_rule(doc: dict, source: str = "") -> Rule:
    try:
        rid, title = str(doc["id"]), str(doc["title"])
        det = dict(doc["detection"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuleError(f"{source}: missing required key {exc}") from exc
    level = str(doc.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"{source}: invalid level {level!r}; expected one of {LEVELS}")
    cond_text = det.pop("condition", None)
    if not cond_text:
        raise RuleError(f"{source}: detection.condition is required")
    if not det:
        raise RuleError(f"{source}: detection needs at least one selection")

    selections: dict[str, list[FieldMatcher]] = {}
    for name, body in det.items():
        if not isinstance(body, dict) or not body:
            raise RuleError(f"{source}: selection {name!r} must be a non-empty object")
        try:
            selections[name] = [FieldMatcher(k, v) for k, v in body.items()]
        except MatcherError as exc:
            raise RuleError(f"{source}: selection {name!r}: {exc}") from exc

    try:
        ast = cond.parse(cond_text)
        # Static check so typos / empty globs fail at load time, not scan time
        # (a dry-run evaluation would be defeated by short-circuiting).
        for ref in cond.names_in(ast):
            if ref == "them":
                continue
            if "*" in ref:
                if not any(fnmatch.fnmatchcase(n, ref) for n in selections):
                    raise cond.ConditionError(f"pattern {ref!r} matches no selections")
            elif ref not in selections:
                raise cond.ConditionError(f"unknown selection {ref!r}")
    except cond.ConditionError as exc:
        raise RuleError(f"{source}: condition: {exc}") from exc

    return Rule(rid, title, level, cond_text, selections, list(doc.get("tags", [])),
                str(doc.get("description", "")), source, ast)


def load_rules(path: str | Path) -> list[Rule]:
    """Load one rule file or every *.json under a directory (recursive)."""
    p = Path(path)
    files = sorted(p.rglob("*.json")) if p.is_dir() else [p]
    if not files:
        raise RuleError(f"no rule files found in {p}")
    rules, seen = [], {}
    for f in files:
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuleError(f"{f}: {exc}") from exc
        for d in doc if isinstance(doc, list) else [doc]:
            rule = parse_rule(d, str(f))
            if rule.id in seen:
                raise RuleError(f"duplicate rule id {rule.id!r} in {f} and {seen[rule.id]}")
            seen[rule.id] = str(f)
            rules.append(rule)
    return rules
