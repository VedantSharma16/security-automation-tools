"""Field matching with Sigma value modifiers (contains, startswith, re, ...)."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

MATCH_MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte"}
COMBINERS = {"all"}


class MatcherError(ValueError):
    pass


def _norm(v: Any) -> str:
    return str(v).lower()


def _wildcard_to_regex(pattern: str) -> re.Pattern:
    out = []
    for ch in pattern:
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


def _make_value_test(modifier: str | None, expected: Any) -> Callable[[Any], bool]:
    if expected is None:
        return lambda actual: actual is None
    if modifier == "contains":
        needle = _norm(expected)
        return lambda a: needle in _norm(a)
    if modifier == "startswith":
        needle = _norm(expected)
        return lambda a: _norm(a).startswith(needle)
    if modifier == "endswith":
        needle = _norm(expected)
        return lambda a: _norm(a).endswith(needle)
    if modifier == "re":
        try:
            rx = re.compile(str(expected), re.IGNORECASE)
        except re.error as exc:
            raise MatcherError(f"invalid regex {expected!r}: {exc}") from exc
        return lambda a: rx.search(str(a)) is not None
    if modifier == "cidr":
        try:
            net = ipaddress.ip_network(str(expected), strict=False)
        except ValueError as exc:
            raise MatcherError(f"invalid CIDR {expected!r}") from exc

        def in_net(a):
            try:
                return ipaddress.ip_address(str(a)) in net
            except ValueError:
                return False

        return in_net
    if modifier in ("gt", "gte", "lt", "lte"):
        ops = {"gt": float.__gt__, "gte": float.__ge__, "lt": float.__lt__, "lte": float.__le__}
        op, limit = ops[modifier], float(expected)

        def cmp(a):
            try:
                return op(float(a), limit)
            except (TypeError, ValueError):
                return False

        return cmp
    # exact match; Sigma allows * and ? wildcards in plain values
    if isinstance(expected, str) and ("*" in expected or "?" in expected):
        rx = _wildcard_to_regex(expected)
        return lambda a: rx.match(str(a)) is not None
    return lambda a: _norm(a) == _norm(expected)


def build_field_matcher(key: str, expected: Any) -> tuple[str, Callable[[dict], bool]]:
    """Return (field_name, predicate(event)) for a ``field|mod|mod: value`` pair."""
    field, *mods = key.split("|")
    if not field:
        raise MatcherError(f"empty field name in {key!r}")
    require_all = "all" in mods
    mods = [m for m in mods if m not in COMBINERS]
    unknown = [m for m in mods if m not in MATCH_MODIFIERS]
    if unknown or len(mods) > 1:
        raise MatcherError(f"unsupported modifiers in {key!r}: {mods}")
    modifier = mods[0] if mods else None
    values = expected if isinstance(expected, list) else [expected]
    tests = [_make_value_test(modifier, v) for v in values]
    combine = all if require_all else any

    def predicate(event: dict) -> bool:
        actual = event.get(field)
        if actual is None:
            return any(v is None for v in values)
        if isinstance(actual, list):
            return combine(any(t(a) for a in actual) for t in tests)
        return combine(t(actual) for t in tests)

    return field, predicate
