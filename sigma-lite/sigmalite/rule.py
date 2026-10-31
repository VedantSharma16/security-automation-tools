"""Sigma rule loading, validation and per-event matching."""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .condition import ConditionError, evaluate, parse_condition, referenced_names

LEVELS = ("informational", "low", "medium", "high", "critical")
VALUE_MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr"}
ALL_MODIFIERS = VALUE_MODIFIERS | {"all"}
ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|[a-z_]+)$")


class RuleError(ValueError):
    pass


def get_field(event: dict, path: str):
    """Fetch a field, supporting literal dotted keys and nested dicts."""
    if path in event:
        return event[path]
    cur = event
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _wild_to_regex(s: str) -> re.Pattern:
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "*?\\":
            out.append(re.escape(s[i + 1])); i += 2; continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


@dataclass
class FieldMatcher:
    field: str
    modifiers: tuple
    values: list

    def __post_init__(self):
        for m in self.modifiers:
            if m not in ALL_MODIFIERS:
                raise RuleError(f"unknown modifier {m!r} on field {self.field!r}")
        if sum(m in VALUE_MODIFIERS for m in self.modifiers) > 1:
            raise RuleError(f"conflicting modifiers on field {self.field!r}")
        self._compiled = [self._compile(v) for v in self.values]

    def _compile(self, v):
        kind = next((m for m in self.modifiers if m in VALUE_MODIFIERS), None)
        if v is None:
            return ("null", None)
        if kind == "re":
            try:
                return ("re", re.compile(str(v)))
            except re.error as e:
                raise RuleError(f"bad regex {v!r}: {e}") from e
        if kind == "cidr":
            try:
                return ("cidr", ipaddress.ip_network(str(v), strict=False))
            except ValueError as e:
                raise RuleError(f"bad CIDR {v!r}") from e
        if kind in ("contains", "startswith", "endswith"):
            return (kind, str(v).lower())
        if isinstance(v, str) and ("*" in v or "?" in v):
            return ("wild", _wild_to_regex(v))
        return ("eq", v)

    def _one(self, actual, comp) -> bool:
        kind, pat = comp
        if kind == "null":
            return actual is None
        if actual is None:
            return False
        if kind == "re":
            return pat.search(str(actual)) is not None
        if kind == "cidr":
            try:
                return ipaddress.ip_address(str(actual)) in pat
            except ValueError:
                return False
        a = str(actual).lower()
        if kind == "contains":
            return pat in a
        if kind == "startswith":
            return a.startswith(pat)
        if kind == "endswith":
            return a.endswith(pat)
        if kind == "wild":
            return pat.match(str(actual)) is not None
        if isinstance(pat, str):
            return a == pat.lower()
        return actual == pat or a == str(pat).lower()

    def matches(self, event: dict) -> bool:
        actual = get_field(event, self.field)
        if isinstance(actual, list):  # any element may satisfy
            test = lambda c: any(self._one(x, c) for x in actual)
        else:
            test = lambda c: self._one(actual, c)
        agg = all if "all" in self.modifiers else any
        return agg(test(c) for c in self._compiled)


def _parse_selection(name: str, body) -> list[list[FieldMatcher]] | list[str]:
    """Return list of AND-groups (OR between groups) or keyword list."""
    if isinstance(body, dict):
        return [[_field_matcher(k, v) for k, v in body.items()]]
    if isinstance(body, list):
        if all(isinstance(x, dict) for x in body):
            return [[_field_matcher(k, v) for k, v in item.items()] for item in body]
        if all(isinstance(x, (str, int)) for x in body):
            return [str(x).lower() for x in body]
    raise RuleError(f"selection {name!r} must be a map, list of maps, or list of keywords")


def _field_matcher(key: str, value) -> FieldMatcher:
    field_name, *mods = str(key).split("|")
    values = value if isinstance(value, list) else [value]
    return FieldMatcher(field_name, tuple(m.lower() for m in mods), values)


@dataclass
class Rule:
    id: str
    title: str
    level: str
    condition_text: str
    selections: dict
    tags: list = field(default_factory=list)
    description: str = ""
    logsource: dict = field(default_factory=dict)
    falsepositives: list = field(default_factory=list)
    source: str = ""

    def __post_init__(self):
        self._cond = parse_condition(self.condition_text)

    @property
    def attack_techniques(self) -> list[str]:
        return sorted(t[7:].upper() for t in self.tags if re.match(r"^attack\.t\d{4}", t))

    @property
    def attack_tactics(self) -> list[str]:
        return sorted(t[7:] for t in self.tags if t.startswith("attack.") and not re.match(r"^attack\.t\d{4}", t))

    def _eval_selection(self, sel, event: dict) -> bool:
        if sel and isinstance(sel[0], str):  # keyword search over whole event
            blob = " ".join(str(v) for v in event.values()).lower()
            return any(k in blob for k in sel)
        return any(all(fm.matches(event) for fm in group) for group in sel)

    def matches(self, event: dict) -> bool:
        results = {n: self._eval_selection(s, event) for n, s in self.selections.items()}
        return evaluate(self._cond, results)

    @classmethod
    def from_dict(cls, d: dict, source: str = "") -> "Rule":
        if not isinstance(d, dict):
            raise RuleError("rule must be a mapping")
        for req in ("title", "detection"):
            if req not in d:
                raise RuleError(f"missing required key {req!r}")
        det = d["detection"]
        if not isinstance(det, dict) or "condition" not in det:
            raise RuleError("detection must contain a 'condition'")
        cond = det["condition"]
        if isinstance(cond, list):
            cond = " or ".join(f"({c})" for c in cond)
        sels = {k: _parse_selection(k, v) for k, v in det.items() if k not in ("condition", "timeframe")}
        if not sels:
            raise RuleError("detection has no selections")
        level = str(d.get("level", "medium")).lower()
        if level not in LEVELS:
            raise RuleError(f"invalid level {level!r}; expected one of {LEVELS}")
        tags = [str(t).lower() for t in d.get("tags", [])]
        for t in tags:
            if t.startswith("attack.") and not ATTACK_TAG.match(t):
                raise RuleError(f"malformed ATT&CK tag {t!r}")
        try:
            rule = cls(
                id=str(d.get("id", d["title"])), title=str(d["title"]), level=level,
                condition_text=str(cond), selections=sels, tags=tags,
                description=str(d.get("description", "")), logsource=d.get("logsource", {}) or {},
                falsepositives=d.get("falsepositives", []) or [], source=source,
            )
            unknown = referenced_names(rule._cond) - set(sels)
            if unknown:
                raise RuleError(f"condition references undefined selection(s): {sorted(unknown)}")
        except ConditionError as e:
            raise RuleError(f"invalid condition: {e}") from e
        return rule


def load_rules(path) -> tuple[list[Rule], list[tuple[str, str]]]:
    """Load rules from a file or directory. Returns (rules, errors)."""
    p = Path(path)
    files = sorted(p.rglob("*.y*ml")) if p.is_dir() else [p]
    rules, errors = [], []
    for f in files:
        try:
            for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
                if doc:
                    rules.append(Rule.from_dict(doc, source=str(f)))
        except (RuleError, yaml.YAMLError) as e:
            errors.append((str(f), str(e).splitlines()[0]))
    return rules, errors
