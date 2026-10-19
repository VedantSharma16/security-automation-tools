"""Field matching with Sigma value modifiers."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cidr", "lt", "lte", "gt", "gte"}


class MatcherError(ValueError):
    pass


def get_field(event: dict, name: str) -> Any:
    """Case-insensitive lookup, with dotted-path support for nested events."""
    if name in event:
        return event[name]
    cur: Any = event
    for part in name.split("."):
        if not isinstance(cur, dict):
            return None
        key = next((k for k in cur if k.lower() == part.lower()), None)
        if key is None:
            return None
        cur = cur[key]
    return cur


def _single(op: str | None, expected: Any) -> Callable[[Any], bool]:
    if expected is None:
        return lambda actual: actual is None
    if op in ("lt", "lte", "gt", "gte"):
        try:
            limit = float(expected)
        except (TypeError, ValueError):
            raise MatcherError(f"modifier {op!r} needs a numeric value, got {expected!r}")
        cmp = {"lt": float.__lt__, "lte": float.__le__, "gt": float.__gt__, "gte": float.__ge__}[op]

        def numeric(actual):
            try:
                return cmp(float(actual), limit)
            except (TypeError, ValueError):
                return False

        return numeric
    if op == "cidr":
        try:
            net = ipaddress.ip_network(str(expected), strict=False)
        except ValueError as exc:
            raise MatcherError(f"bad CIDR {expected!r}: {exc}")

        def in_net(actual):
            try:
                return ipaddress.ip_address(str(actual)) in net
            except ValueError:
                return False

        return in_net
    if op == "re":
        try:
            rx = re.compile(str(expected), re.IGNORECASE)
        except re.error as exc:
            raise MatcherError(f"bad regex {expected!r}: {exc}")
        return lambda actual: actual is not None and rx.search(str(actual)) is not None

    want = str(expected).lower()
    if op == "contains":
        return lambda a: a is not None and want in str(a).lower()
    if op == "startswith":
        return lambda a: a is not None and str(a).lower().startswith(want)
    if op == "endswith":
        return lambda a: a is not None and str(a).lower().endswith(want)
    # Plain equality, case-insensitive, with Sigma '*' / '?' wildcards.
    if "*" in want or "?" in want:
        rx = re.compile("^" + "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in want) + "$")
        return lambda a: a is not None and rx.match(str(a).lower()) is not None
    return lambda a: a is not None and str(a).lower() == want


def build_field_matcher(key: str, values: Any) -> Callable[[dict], bool]:
    """Build a predicate for one ``field|mod|mod: value(s)`` detection item."""
    field, *mods = key.split("|")
    unknown = [m for m in mods if m not in MODIFIERS]
    if unknown:
        raise MatcherError(f"unknown modifier(s) {unknown} in {key!r}")
    require_all = "all" in mods
    ops = [m for m in mods if m != "all"]
    if len(ops) > 1:
        raise MatcherError(f"conflicting modifiers in {key!r}")
    op = ops[0] if ops else None
    vals = values if isinstance(values, list) else [values]
    if not vals:
        raise MatcherError(f"empty value list for {key!r}")
    preds = [_single(op, v) for v in vals]
    combine = all if require_all else any
    return lambda event: combine(p(get_field(event, field)) for p in preds)
