"""Sigma rule model: loading, validation, and ATT&CK tag extraction."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import yamlsubset
from .condition import Condition, parse_condition

LEVELS = ("informational", "low", "medium", "high", "critical")
MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cased"}


class RuleError(ValueError):
    pass


@dataclass
class Matcher:
    field: str
    modifiers: tuple[str, ...]
    values: list

    def __post_init__(self):
        for m in self.modifiers:
            if m not in MODIFIERS:
                raise RuleError(f"unsupported modifier {m!r} on field {self.field!r}")
        if "re" in self.modifiers:
            flags = 0 if "cased" in self.modifiers else re.IGNORECASE
            try:
                self._res = [re.compile(str(v), flags) for v in self.values if v is not None]
            except re.error as e:
                raise RuleError(f"invalid regex on {self.field!r}: {e}") from e

    def _one(self, actual, expected) -> bool:
        if expected is None:
            return actual is None or actual == ""
        if actual is None:
            return False
        if "re" in self.modifiers:
            return False  # handled in matches()
        a, e = str(actual), str(expected)
        if "cased" not in self.modifiers:
            a, e = a.lower(), e.lower()
        if "contains" in self.modifiers:
            return e in a
        if "startswith" in self.modifiers:
            return a.startswith(e)
        if "endswith" in self.modifiers:
            return a.endswith(e)
        if "*" in e or "?" in e:
            pat = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in e)
            return re.fullmatch(pat, a, re.DOTALL) is not None
        return a == e

    def matches(self, event: dict) -> bool:
        actual = _lookup(event, self.field)
        if "re" in self.modifiers:
            if actual is None:
                return False
            hits = [bool(r.search(str(actual))) for r in self._res]
        else:
            hits = [self._one(actual, v) for v in self.values]
        return all(hits) if "all" in self.modifiers else any(hits)


def _lookup(event: dict, name: str):
    """Exact key, then case-insensitive key, then dotted path into nested maps."""
    if name in event:
        return event[name]
    lowered = {k.lower(): k for k in event}
    if name.lower() in lowered:
        return event[lowered[name.lower()]]
    cur = event
    for part in name.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


@dataclass
class Selection:
    """AND across matchers, or OR across alternative maps (list of maps)."""
    alternatives: list[list[Matcher]]
    keywords: list[str] = field(default_factory=list)

    def matches(self, event: dict) -> bool:
        if self.keywords:
            blob = " ".join(str(v) for v in event.values()).lower()
            if any(k.lower() in blob for k in self.keywords):
                return True
        return any(all(m.matches(event) for m in alt) for alt in self.alternatives if alt)


@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str
    tags: list[str]
    selections: dict[str, Selection]
    condition: Condition
    source: str = ""

    @property
    def attack_techniques(self) -> list[str]:
        return sorted({t.split(".", 1)[1].upper() for t in self.tags if t.lower().startswith("attack.t")})

    @property
    def attack_tactics(self) -> list[str]:
        return sorted({t.split(".", 1)[1] for t in self.tags
                       if t.lower().startswith("attack.") and not t.lower().startswith("attack.t1")
                       and not re.match(r"attack\.t\d", t.lower())})

    def matches(self, event: dict) -> bool:
        return self.condition.evaluate(self.selections, event)


def _build_matcher(key: str, value) -> Matcher:
    field_name, *mods = key.split("|")
    values = value if isinstance(value, list) else [value]
    return Matcher(field_name, tuple(m.lower() for m in mods), values)


def _build_selection(name: str, body) -> Selection:
    if isinstance(body, dict):
        return Selection([[_build_matcher(k, v) for k, v in body.items()]])
    if isinstance(body, list):
        if all(isinstance(x, dict) for x in body):
            return Selection([[_build_matcher(k, v) for k, v in d.items()] for d in body])
        return Selection([], keywords=[str(x) for x in body])
    raise RuleError(f"selection {name!r} must be a map or list")


def rule_from_dict(data: dict, source: str = "") -> Rule:
    if not isinstance(data, dict):
        raise RuleError("rule must be a mapping")
    for req in ("title", "detection"):
        if req not in data:
            raise RuleError(f"missing required field {req!r}")
    det = data["detection"]
    if not isinstance(det, dict) or "condition" not in det:
        raise RuleError("detection must contain a 'condition'")
    level = str(data.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"invalid level {level!r}; expected one of {LEVELS}")
    selections = {k: _build_selection(k, v) for k, v in det.items() if k != "condition"}
    cond_src = det["condition"]
    if isinstance(cond_src, list):
        cond_src = " or ".join(f"({c})" for c in cond_src)
    cond = parse_condition(str(cond_src))
    unknown = cond.referenced_names() - set(selections)
    if unknown:
        raise RuleError(f"condition references undefined selection(s): {sorted(unknown)}")
    tags = data.get("tags") or []
    return Rule(
        id=str(data.get("id", data["title"])), title=str(data["title"]), level=level,
        description=str(data.get("description") or ""), tags=[str(t) for t in tags],
        selections=selections, condition=cond, source=source,
    )


def load_rule_file(path: str | Path) -> Rule:
    p = Path(path)
    try:
        return rule_from_dict(yamlsubset.loads(p.read_text(encoding="utf-8")), source=str(p))
    except (yamlsubset.YamlError, RuleError) as e:
        raise RuleError(f"{p}: {e}") from e


def load_rules(path: str | Path) -> list[Rule]:
    p = Path(path)
    files = [p] if p.is_file() else sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")])
    if not files:
        raise RuleError(f"no rule files found under {p}")
    return [load_rule_file(f) for f in files]
