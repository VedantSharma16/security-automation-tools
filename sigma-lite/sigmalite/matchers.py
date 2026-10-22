"""Field matching with Sigma value modifiers.

Supported modifiers: contains, startswith, endswith, all, re, cidr,
lt, lte, gt, gte, exists. Plain string comparison is case-insensitive and
honours the ``*`` and ``?`` wildcards.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

_MISSING = object()
VALUE_MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "lt", "lte", "gt", "gte", "exists"}
ALL_MODIFIERS = VALUE_MODIFIERS | {"all"}


class MatcherError(ValueError):
    pass


def get_field(event: dict, path: str) -> Any:
    """Resolve a field, trying a literal key first then dotted nesting."""
    if path in event:
        return event[path]
    cur: Any = event
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _wildcard_regex(pattern: str) -> re.Pattern:
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


def _build_single(modifier: str | None, expected: Any) -> Callable[[Any], bool]:
    if expected is None:
        return lambda v: v is None
    if modifier in ("lt", "lte", "gt", "gte"):
        try:
            num = float(expected)
        except (TypeError, ValueError):
            raise MatcherError(f"modifier {modifier!r} needs a numeric value, got {expected!r}")
        ops = {"lt": lambda a: a < num, "lte": lambda a: a <= num,
               "gt": lambda a: a > num, "gte": lambda a: a >= num}

        def numeric(v: Any) -> bool:
            try:
                return ops[modifier](float(v))
            except (TypeError, ValueError):
                return False

        return numeric
    if modifier == "re":
        try:
            rx = re.compile(str(expected))
        except re.error as exc:
            raise MatcherError(f"invalid regex {expected!r}: {exc}")
        return lambda v: isinstance(v, (str, int, float)) and rx.search(str(v)) is not None
    if modifier == "cidr":
        try:
            net = ipaddress.ip_network(str(expected), strict=False)
        except ValueError as exc:
            raise MatcherError(f"invalid CIDR {expected!r}: {exc}")

        def in_net(v: Any) -> bool:
            try:
                return ipaddress.ip_address(str(v)) in net
            except ValueError:
                return False

        return in_net

    text = str(expected)
    if modifier == "contains":
        text = f"*{text}*"
    elif modifier == "startswith":
        text = f"{text}*"
    elif modifier == "endswith":
        text = f"*{text}"
    rx = _wildcard_regex(text)
    return lambda v: isinstance(v, (str, int, float, bool)) and rx.match(str(v)) is not None


class FieldMatcher:
    """One ``field|modifier: value(s)`` clause."""

    def __init__(self, key: str, expected: Any):
        field, *mods = key.split("|")
        unknown = [m for m in mods if m not in ALL_MODIFIERS]
        if unknown:
            raise MatcherError(f"unsupported modifier(s) {unknown} in {key!r}")
        self.field = field
        self.require_all = "all" in mods
        value_mods = [m for m in mods if m != "all"]
        if len(value_mods) > 1:
            raise MatcherError(f"only one value modifier allowed in {key!r}")
        self.modifier = value_mods[0] if value_mods else None
        self.exists_expected = None
        if self.modifier == "exists":
            if not isinstance(expected, bool):
                raise MatcherError(f"'exists' needs true/false in {key!r}")
            self.exists_expected = expected
            self.tests: list = []
            return
        values = expected if isinstance(expected, list) else [expected]
        if not values:
            raise MatcherError(f"empty value list for {key!r}")
        self.tests = [_build_single(self.modifier, v) for v in values]

    def matches(self, event: dict) -> bool:
        raw = get_field(event, self.field)
        if self.modifier == "exists":
            return (raw is not _MISSING) == self.exists_expected
        if raw is _MISSING:
            # ``field: null`` matches an absent field.
            return any(t(None) for t in self.tests) and self.modifier is None
        candidates = raw if isinstance(raw, list) else [raw]
        combine = all if self.require_all else any
        if self.require_all:
            return all(any(t(c) for c in candidates) for t in self.tests)
        return combine(t(c) for t in self.tests for c in candidates)


class KeywordMatcher:
    """Free-text keywords: match if any value appears in any string field."""

    def __init__(self, values: list):
        self.tests = [_build_single("contains", v) for v in values]

    def matches(self, event: dict) -> bool:
        def walk(obj: Any):
            if isinstance(obj, dict):
                for v in obj.values():
                    yield from walk(v)
            elif isinstance(obj, list):
                for v in obj:
                    yield from walk(v)
            elif isinstance(obj, str):
                yield obj

        return any(t(s) for s in walk(event) for t in self.tests)
