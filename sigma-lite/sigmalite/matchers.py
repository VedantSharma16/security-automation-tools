"""Field matching with Sigma-style modifiers (``field|contains|all``)."""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from typing import Any

SUPPORTED_MODIFIERS = {
    "contains", "startswith", "endswith", "re", "cidr", "all", "gt", "gte", "lt", "lte",
}
_OPERATORS = {"contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte"}


class MatcherError(ValueError):
    pass


@lru_cache(maxsize=512)
def _regex(pattern: str) -> re.Pattern:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise MatcherError(f"invalid regex {pattern!r}: {exc}") from exc


def split_field(key: str) -> tuple[str, str | None, bool]:
    """``'CommandLine|contains|all'`` -> (``'CommandLine'``, ``'contains'``, True)."""
    field, *mods = key.split("|")
    if not field:
        raise MatcherError(f"empty field name in {key!r}")
    unknown = [m for m in mods if m not in SUPPORTED_MODIFIERS]
    if unknown:
        raise MatcherError(f"unsupported modifier(s) {unknown} in {key!r}")
    ops = [m for m in mods if m in _OPERATORS]
    if len(ops) > 1:
        raise MatcherError(f"multiple operators in {key!r}")
    return field, (ops[0] if ops else None), "all" in mods


def get_field(event: dict, name: str) -> Any:
    """Case-insensitive field lookup, with dotted-path support for nested events."""
    if name in event:
        return event[name]
    lowered = name.lower()
    for k, v in event.items():
        if k.lower() == lowered:
            return v
    if "." in name:
        cur: Any = event
        for part in name.split("."):
            if not isinstance(cur, dict):
                return None
            cur = get_field(cur, part)
            if cur is None:
                return None
        return cur
    return None


def _one(actual: Any, op: str | None, expected: Any) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    if op in ("gt", "gte", "lt", "lte"):
        try:
            a, e = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[op]
    if op == "cidr":
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    a, e = str(actual), str(expected)
    if op == "re":
        return _regex(e).search(a) is not None
    a, e = a.lower(), e.lower()
    if op == "contains":
        return e in a
    if op == "startswith":
        return a.startswith(e)
    if op == "endswith":
        return a.endswith(e)
    # No operator: case-insensitive equality with * and ? wildcards.
    if "*" in e or "?" in e:
        pattern = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in e)
        return re.fullmatch(pattern, a, re.DOTALL) is not None
    return a == e


def match_field(event: dict, key: str, expected: Any) -> bool:
    field, op, require_all = split_field(key)
    actual = get_field(event, field)
    values = expected if isinstance(expected, list) else [expected]
    if not values:
        return False
    results = (_one(actual, op, v) for v in values)
    return all(results) if require_all else any(results)
