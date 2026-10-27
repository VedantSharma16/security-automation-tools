"""Field matching with Sigma-style modifiers (field|contains|all, field|re, ...)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "all", "gt", "gte", "lt", "lte"}
_MAX_PATTERN_LEN = 500


class MatcherError(ValueError):
    pass


def get_field(event: dict, path: str) -> Any:
    """Case-insensitive lookup supporting dotted paths for nested events."""
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        if part in cur:
            cur = cur[part]
            continue
        lowered = {k.lower(): v for k, v in cur.items() if isinstance(k, str)}
        if part.lower() not in lowered:
            return None
        cur = lowered[part.lower()]
    return cur


def _compile_one(op: str, expected: Any) -> Callable[[Any], bool]:
    if op == "re":
        if not isinstance(expected, str) or len(expected) > _MAX_PATTERN_LEN:
            raise MatcherError("regex must be a string under %d chars" % _MAX_PATTERN_LEN)
        try:
            rx = re.compile(expected, re.IGNORECASE)
        except re.error as exc:
            raise MatcherError(f"invalid regex {expected!r}: {exc}") from exc
        return lambda v: rx.search(str(v)) is not None
    if op == "cidr":
        try:
            net = ipaddress.ip_network(str(expected), strict=False)
        except ValueError as exc:
            raise MatcherError(f"invalid CIDR {expected!r}") from exc

        def in_net(v: Any) -> bool:
            try:
                return ipaddress.ip_address(str(v)) in net
            except ValueError:
                return False

        return in_net
    if op in ("gt", "gte", "lt", "lte"):
        if isinstance(expected, bool) or not isinstance(expected, (int, float)):
            raise MatcherError(f"{op} requires a numeric value")
        cmp = {"gt": float.__gt__, "gte": float.__ge__, "lt": float.__lt__, "lte": float.__le__}[op]

        def num(v: Any) -> bool:
            try:
                return cmp(float(v), float(expected))
            except (TypeError, ValueError):
                return False

        return num

    exp = "" if expected is None else str(expected).lower()
    if expected is None:
        return lambda v: v is None
    if op == "contains":
        return lambda v: v is not None and exp in str(v).lower()
    if op == "startswith":
        return lambda v: v is not None and str(v).lower().startswith(exp)
    if op == "endswith":
        return lambda v: v is not None and str(v).lower().endswith(exp)
    return lambda v: v is not None and str(v).lower() == exp  # exact, case-insensitive


class FieldMatcher:
    """One `field|mod: value(s)` entry. Multiple values are OR'd unless `all`."""

    def __init__(self, key: str, expected: Any):
        field, *mods = key.split("|")
        unknown = [m for m in mods if m not in MODIFIERS]
        if not field or unknown:
            raise MatcherError(f"bad field spec {key!r}" + (f" (unknown modifier {unknown})" if unknown else ""))
        require_all = "all" in mods
        mods = [m for m in mods if m != "all"]
        if len(mods) > 1:
            raise MatcherError(f"only one match modifier allowed in {key!r}")
        op = mods[0] if mods else "equals"
        values = expected if isinstance(expected, list) else [expected]
        if not values:
            raise MatcherError(f"empty value list for {key!r}")
        self.field, self.key = field, key
        self._tests = [_compile_one(op, v) for v in values]
        self._combine = all if require_all else any

    def matches(self, event: dict) -> bool:
        value = get_field(event, self.field)
        if isinstance(value, list):  # any element satisfying the whole test
            return any(self._combine(t(v) for t in self._tests) for v in value)
        return self._combine(t(value) for t in self._tests)
