"""Field matching with Sigma-style modifiers (``Field|contains|all: [...]``)."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

SUPPORTED_MODIFIERS = {
    "contains", "startswith", "endswith", "re", "all", "cidr",
    "lt", "lte", "gt", "gte", "exists",
}
_OPERATORS = {"contains", "startswith", "endswith", "re", "cidr", "lt", "lte", "gt", "gte", "exists"}


class RuleError(ValueError):
    """Raised for malformed rules."""


def parse_field(key: str) -> tuple[str, list[str]]:
    """Split ``Image|endswith|all`` into (``Image``, [``endswith``, ``all``])."""
    field, *mods = key.split("|")
    if not field:
        raise RuleError(f"empty field name in {key!r}")
    for m in mods:
        if m not in SUPPORTED_MODIFIERS:
            raise RuleError(f"unsupported modifier {m!r} in {key!r}")
    if sum(m in _OPERATORS for m in mods) > 1:
        raise RuleError(f"multiple operators in {key!r}")
    return field, mods


def get_field(event: dict, field: str) -> Any:
    """Case-insensitive lookup, with dotted-path support for nested events."""
    if field in event:
        return event[field]
    lower = field.lower()
    for k, v in event.items():
        if k.lower() == lower:
            return v
    if "." in field:
        cur: Any = event
        for part in field.split("."):
            if not isinstance(cur, dict):
                return None
            nxt = next((v for k, v in cur.items() if k.lower() == part.lower()), None)
            cur = nxt
        return cur
    return None


def _wildcard_to_regex(pattern: str) -> re.Pattern:
    out = []
    for ch in pattern:
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


def _num(x: Any) -> float:
    return float(x)


def _build_single(op: str | None, expected: Any) -> Callable[[Any], bool]:
    """Return a predicate testing one actual value against one expected value."""
    if expected is None:
        return lambda a: a is None or a == ""
    if op == "re":
        try:
            rx = re.compile(str(expected), re.IGNORECASE)
        except re.error as exc:
            raise RuleError(f"invalid regex {expected!r}: {exc}") from exc
        return lambda a: rx.search(str(a)) is not None
    if op == "cidr":
        try:
            net = ipaddress.ip_network(str(expected), strict=False)
        except ValueError as exc:
            raise RuleError(f"invalid CIDR {expected!r}") from exc

        def in_net(a: Any) -> bool:
            try:
                return ipaddress.ip_address(str(a)) in net
            except ValueError:
                return False
        return in_net
    if op in ("lt", "lte", "gt", "gte"):
        try:
            exp = _num(expected)
        except (TypeError, ValueError) as exc:
            raise RuleError(f"{op} needs a numeric value, got {expected!r}") from exc
        cmp = {"lt": lambda a: a < exp, "lte": lambda a: a <= exp,
               "gt": lambda a: a > exp, "gte": lambda a: a >= exp}[op]

        def numeric(a: Any) -> bool:
            try:
                return cmp(_num(a))
            except (TypeError, ValueError):
                return False
        return numeric

    text = str(expected)
    if op == "contains":
        text = f"*{text}*"
    elif op == "startswith":
        text = f"{text}*"
    elif op == "endswith":
        text = f"*{text}"
    if not isinstance(expected, str):  # numbers/bools: exact, type-tolerant
        return lambda a: str(a).lower() == text.lower()
    rx = _wildcard_to_regex(text)
    return lambda a: rx.match(str(a)) is not None


def compile_field_matcher(key: str, expected: Any) -> Callable[[dict], bool]:
    """Compile one ``key: value(s)`` pair of a selection into an event predicate."""
    field, mods = parse_field(key)
    op = next((m for m in mods if m in _OPERATORS), None)
    require_all = "all" in mods

    if op == "exists":
        want = bool(expected)
        return lambda ev: (get_field(ev, field) is not None) == want

    values = expected if isinstance(expected, list) else [expected]
    if not values:
        raise RuleError(f"empty value list for {key!r}")
    preds = [_build_single(op, v) for v in values]

    def match(event: dict) -> bool:
        actual = get_field(event, field)
        if actual is None and not any(v is None for v in values):
            return False
        actuals = actual if isinstance(actual, list) else [actual]
        hit = lambda p: any(p(a) for a in actuals)
        return all(hit(p) for p in preds) if require_all else any(hit(p) for p in preds)

    return match
