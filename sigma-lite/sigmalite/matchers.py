"""Field matching with Sigma value modifiers.

Supported modifiers: contains, startswith, endswith, re, all, cidr,
lt, lte, gt, gte. Plain values support ``*`` and ``?`` wildcards and match
case-insensitively, as in Sigma.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

MATCH_MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr",
                   "lt", "lte", "gt", "gte"}
KNOWN_MODIFIERS = MATCH_MODIFIERS | {"all"}
MAX_REGEX_LEN = 500


class ModifierError(ValueError):
    pass


def _wildcard_to_regex(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


def _num(x: Any) -> float | None:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def build_value_matcher(value: Any, modifier: str | None) -> Callable[[Any], bool]:
    """Return a predicate testing one event field value against one rule value."""
    if value is None:
        return lambda v: v is None or v == ""
    if modifier in ("lt", "lte", "gt", "gte"):
        target = _num(value)
        if target is None:
            raise ModifierError(f"'{modifier}' needs a numeric value, got {value!r}")
        ops = {"lt": lambda a: a < target, "lte": lambda a: a <= target,
               "gt": lambda a: a > target, "gte": lambda a: a >= target}
        op = ops[modifier]
        return lambda v: (n := _num(v)) is not None and op(n)
    if modifier == "cidr":
        try:
            net = ipaddress.ip_network(str(value), strict=False)
        except ValueError as e:
            raise ModifierError(f"bad CIDR {value!r}: {e}") from e

        def cidr(v: Any) -> bool:
            try:
                return ipaddress.ip_address(str(v)) in net
            except ValueError:
                return False
        return cidr
    text = str(value)
    if modifier == "re":
        if len(text) > MAX_REGEX_LEN:
            raise ModifierError("regex too long")
        try:
            rx = re.compile(text, re.IGNORECASE)
        except re.error as e:
            raise ModifierError(f"bad regex {text!r}: {e}") from e
        return lambda v: v is not None and rx.search(str(v)) is not None
    if modifier in ("contains", "startswith", "endswith"):
        text = {"contains": f"*{text}*", "startswith": f"{text}*",
                "endswith": f"*{text}"}[modifier]
    if not any(c in text for c in "*?"):
        low = text.lower()
        return lambda v: v is not None and str(v).lower() == low
    rx = _wildcard_to_regex(text)
    return lambda v: v is not None and rx.match(str(v)) is not None


def get_field(event: dict, name: str) -> Any:
    """Look up a field; tries the literal key (case-insensitive), then dotted paths."""
    if name in event:
        return event[name]
    low = name.lower()
    for k, v in event.items():
        if isinstance(k, str) and k.lower() == low:
            return v
    if "." in name:
        cur: Any = event
        for part in name.split("."):
            if not isinstance(cur, dict):
                return None
            cur = get_field(cur, part)
        return cur
    return None


class FieldMatcher:
    """One ``field|modifiers: values`` entry of a selection."""

    def __init__(self, key: str, values: Any):
        field, *mods = key.split("|")
        unknown = [m for m in mods if m not in KNOWN_MODIFIERS]
        if unknown:
            raise ModifierError(f"unknown modifier(s) {unknown} in {key!r}")
        match_mods = [m for m in mods if m in MATCH_MODIFIERS]
        if len(match_mods) > 1:
            raise ModifierError(f"conflicting modifiers in {key!r}")
        self.field = field
        self.require_all = "all" in mods
        vals = values if isinstance(values, list) else [values]
        mod = match_mods[0] if match_mods else None
        self._preds = [build_value_matcher(v, mod) for v in vals]

    def matches(self, event: dict) -> bool:
        actual = get_field(event, self.field)
        candidates = actual if isinstance(actual, list) else [actual]
        agg = all if self.require_all else any
        return agg(any(p(c) for c in candidates) for p in self._preds)


class Selection:
    """A named selection: a map (AND of fields) or a list of maps (OR)."""

    def __init__(self, spec: Any):
        maps = spec if isinstance(spec, list) else [spec]
        if not maps or not all(isinstance(m, dict) and m for m in maps):
            raise ModifierError("selection must be a non-empty map or list of maps")
        self._groups = [[FieldMatcher(k, v) for k, v in m.items()] for m in maps]

    def matches(self, event: dict) -> bool:
        return any(all(f.matches(event) for f in g) for g in self._groups)
