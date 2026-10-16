"""Field matching with Sigma-style modifiers (``field|contains|all``)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

_OPS = {"contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte"}
_FLAGS = {"all"}


class MatchError(ValueError):
    pass


def parse_key(key: str) -> tuple[str, str, bool]:
    """Split ``Image|endswith|all`` into (field, operator, require_all)."""
    field, *mods = key.split("|")
    if not field:
        raise MatchError(f"empty field name in {key!r}")
    op, require_all = "equals", False
    for mod in mods:
        if mod in _OPS:
            if op != "equals":
                raise MatchError(f"multiple operators in {key!r}")
            op = mod
        elif mod in _FLAGS:
            require_all = True
        else:
            raise MatchError(f"unknown modifier {mod!r} in {key!r}")
    return field, op, require_all


def get_field(event: dict, field: str) -> Any:
    """Case-insensitive lookup that also supports dotted paths."""
    if field in event:
        return event[field]
    cur: Any = event
    for part in field.split("."):
        if not isinstance(cur, dict):
            return None
        match = next((k for k in cur if k.lower() == part.lower()), None)
        if match is None:
            return None
        cur = cur[match]
    return cur


def _compile(op: str, expected: Any) -> Callable[[Any], bool]:
    if expected is None:
        return lambda v: v is None
    if op == "re":
        try:
            rx = re.compile(str(expected), re.IGNORECASE)
        except re.error as exc:
            raise MatchError(f"bad regex {expected!r}: {exc}") from exc
        return lambda v: v is not None and rx.search(str(v)) is not None
    if op == "cidr":
        try:
            net = ipaddress.ip_network(str(expected), strict=False)
        except ValueError as exc:
            raise MatchError(f"bad CIDR {expected!r}") from exc

        def in_net(v: Any) -> bool:
            try:
                return ipaddress.ip_address(str(v)) in net
            except ValueError:
                return False

        return in_net
    if op in {"gt", "gte", "lt", "lte"}:
        try:
            num = float(expected)
        except (TypeError, ValueError) as exc:
            raise MatchError(f"{op} needs a number, got {expected!r}") from exc
        cmp = {
            "gt": lambda a: a > num,
            "gte": lambda a: a >= num,
            "lt": lambda a: a < num,
            "lte": lambda a: a <= num,
        }[op]

        def numeric(v: Any) -> bool:
            try:
                return cmp(float(v))
            except (TypeError, ValueError):
                return False

        return numeric

    want = str(expected).lower()
    if op == "contains":
        return lambda v: v is not None and want in str(v).lower()
    if op == "startswith":
        return lambda v: v is not None and str(v).lower().startswith(want)
    if op == "endswith":
        return lambda v: v is not None and str(v).lower().endswith(want)
    # equals; supports * and ? wildcards like Sigma
    if "*" in want or "?" in want:
        rx = re.compile(
            "^" + re.escape(want).replace(r"\*", ".*").replace(r"\?", ".") + "$", re.S
        )
        return lambda v: v is not None and rx.match(str(v).lower()) is not None
    return lambda v: v is not None and str(v).lower() == want


class FieldMatcher:
    """One ``field|modifiers: value(s)`` clause."""

    def __init__(self, key: str, value: Any):
        self.field, self.op, self.require_all = parse_key(key)
        values = value if isinstance(value, list) else [value]
        if not values:
            raise MatchError(f"no values for {key!r}")
        self._tests = [_compile(self.op, v) for v in values]

    def matches(self, event: dict) -> bool:
        actual = get_field(event, self.field)
        results = (t(actual) for t in self._tests)
        return all(results) if self.require_all else any(results)


class Selection:
    """AND of field matchers (a dict) or OR of dicts (a list of dicts)."""

    def __init__(self, spec: Any):
        groups = spec if isinstance(spec, list) else [spec]
        if not groups or not all(isinstance(g, dict) and g for g in groups):
            raise MatchError("selection must be a non-empty mapping or list of mappings")
        self._groups = [[FieldMatcher(k, v) for k, v in g.items()] for g in groups]

    def matches(self, event: dict) -> bool:
        return any(all(m.matches(event) for m in g) for g in self._groups)
