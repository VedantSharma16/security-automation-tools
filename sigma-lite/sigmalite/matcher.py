"""Field matching with Sigma value modifiers (``Field|contains|all`` etc.)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable

MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cidr", "exists"}
_OPS: dict[str, Callable[[str, str], bool]] = {
    "equals": lambda v, p: v == p,
    "contains": lambda v, p: p in v,
    "startswith": lambda v, p: v.startswith(p),
    "endswith": lambda v, p: v.endswith(p),
}


def get_field(event: dict, path: str) -> Any:
    """Resolve a dotted path (``process.parent.name``); flat dotted keys win."""
    if path in event:
        return event[path]
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


@dataclass
class FieldMatcher:
    field: str
    op: str
    patterns: list
    require_all: bool = False

    def _one(self, value: Any, pat: Any) -> bool:
        if self.op == "exists":
            return (value is not None) == bool(pat)
        if value is None:
            return pat is None
        if self.op == "cidr":
            try:
                return ipaddress.ip_address(str(value)) in ipaddress.ip_network(pat, strict=False)
            except ValueError:
                return False
        if self.op == "re":
            return re.search(pat, str(value)) is not None
        if isinstance(pat, (int, float)) and not isinstance(pat, bool):
            return value == pat
        return _OPS[self.op](str(value).lower(), str(pat).lower())  # Sigma is case-insensitive

    def matches(self, event: dict) -> bool:
        value = get_field(event, self.field)
        values = value if isinstance(value, list) else [value]
        hit = lambda p: any(self._one(v, p) for v in values)  # noqa: E731
        return all(map(hit, self.patterns)) if self.require_all else any(map(hit, self.patterns))


@dataclass
class Selection:
    """AND across field matchers; a list of maps in the spec is OR across maps."""
    alternatives: list[list[FieldMatcher]]

    @classmethod
    def from_spec(cls, spec: Any) -> "Selection":
        maps = spec if isinstance(spec, list) else [spec]
        alts = []
        for m in maps:
            if not isinstance(m, dict) or not m:
                raise ValueError("selection must be a non-empty map or list of maps")
            alts.append([_parse_field(k, v) for k, v in m.items()])
        return cls(alts)

    def matches(self, event: dict) -> bool:
        return any(all(fm.matches(event) for fm in alt) for alt in self.alternatives)


def _parse_field(key: str, value: Any) -> FieldMatcher:
    name, *mods = key.split("|")
    bad = [m for m in mods if m not in MODIFIERS]
    if bad:
        raise ValueError(f"unknown modifier(s) {bad} on {name!r}")
    ops = [m for m in mods if m != "all"]
    if len(ops) > 1:
        raise ValueError(f"conflicting modifiers on {name!r}")
    op = ops[0] if ops else "equals"
    pats = value if isinstance(value, list) else [value]
    if op == "re":
        for p in pats:
            try:
                re.compile(p)
            except re.error as exc:
                raise ValueError(f"bad regex {p!r}: {exc}") from None
    return FieldMatcher(name, op, pats, "all" in mods)
