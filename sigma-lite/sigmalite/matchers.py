"""Field matching with Sigma value modifiers (contains, startswith, re, ...)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

_TRANSFORMS = {"contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte"}
_FLAGS = {"all", "cased"}


class ModifierError(ValueError):
    """Raised for unknown or incompatible field modifiers."""


def get_field(event: dict, path: str) -> Any:
    """Look up ``path`` in ``event``: exact key first, then dotted nesting."""
    if path in event:
        return event[path]
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _wildcard_regex(pattern: str, cased: bool, lead: bool = False, trail: bool = False) -> re.Pattern:
    """Translate Sigma wildcards (* and ?, backslash-escapable) to a regex.

    ``lead``/``trail`` add an implicit ``.*`` that is never subject to escaping, so a
    value ending in a Windows path separator still works with ``|contains``.
    """
    out, i = ([".*"] if lead else []), 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    if trail:
        out.append(".*")
    return re.compile("".join(out), 0 if cased else re.IGNORECASE | re.DOTALL)


def _single(transform: str | None, expected: Any, cased: bool) -> Callable[[Any], bool]:
    """Build a predicate for one expected value."""
    if expected is None:
        return lambda actual: actual is None
    if transform in ("gt", "gte", "lt", "lte"):
        ops = {"gt": float.__gt__, "gte": float.__ge__, "lt": float.__lt__, "lte": float.__le__}
        op, bound = ops[transform], float(expected)

        def numeric(actual: Any) -> bool:
            try:
                return op(float(actual), bound)
            except (TypeError, ValueError):
                return False

        return numeric
    if transform == "cidr":
        net = ipaddress.ip_network(str(expected), strict=False)

        def in_net(actual: Any) -> bool:
            try:
                return ipaddress.ip_address(str(actual)) in net
            except ValueError:
                return False

        return in_net
    if transform == "re":
        rx = re.compile(str(expected), 0 if cased else re.IGNORECASE)
        return lambda actual: actual is not None and rx.search(str(actual)) is not None

    text = str(expected)
    lead = transform in ("contains", "endswith")
    trail = transform in ("contains", "startswith")
    if isinstance(expected, (int, float, bool)) and transform is None:
        return lambda actual: actual is not None and str(actual).lower() == text.lower()
    rx = _wildcard_regex(text, cased, lead, trail)
    return lambda actual: actual is not None and rx.fullmatch(str(actual)) is not None


def build_field_matcher(key: str, value: Any) -> Callable[[dict], bool]:
    """Compile a selection entry like ``CommandLine|contains|all: [...]``."""
    field, *mods = key.split("|")
    transforms = [m for m in mods if m in _TRANSFORMS]
    flags = [m for m in mods if m in _FLAGS]
    unknown = [m for m in mods if m not in _TRANSFORMS | _FLAGS]
    if unknown:
        raise ModifierError(f"unsupported modifier(s) {unknown} in {key!r}")
    if len(transforms) > 1:
        raise ModifierError(f"multiple transforms {transforms} in {key!r}")
    transform = transforms[0] if transforms else None
    cased, require_all = "cased" in flags, "all" in flags

    values = value if isinstance(value, list) else [value]
    preds = [_single(transform, v, cased) for v in values]
    combine = all if require_all else any

    def match(event: dict) -> bool:
        actual = get_field(event, field)
        candidates = actual if isinstance(actual, list) else [actual]
        return any(combine(p(c) for p in preds) for c in candidates)

    return match
