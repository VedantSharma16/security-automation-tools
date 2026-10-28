"""Field matching with Sigma value modifiers.

Supported modifiers: ``contains``, ``startswith``, ``endswith``, ``re``,
``cidr``, ``all`` (require every value instead of any), ``windash``-free.
Plain matches are case-insensitive, like Sigma's reference behaviour.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

MATCH_MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr"}
OTHER_MODIFIERS = {"all"}


class MatcherError(ValueError):
    pass


def get_field(event: dict, name: str) -> Any:
    """Look up a field; supports exact keys and dotted paths into nested dicts."""
    if name in event:
        return event[name]
    cur: Any = event
    for part in name.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _value_matcher(mod: str | None, expected: Any) -> Callable[[Any], bool]:
    if expected is None:
        return lambda actual: actual is None
    if mod == "re":
        try:
            pattern = re.compile(str(expected), re.IGNORECASE)
        except re.error as exc:
            raise MatcherError(f"invalid regex {expected!r}: {exc}") from exc
        return lambda actual: actual is not None and bool(pattern.search(str(actual)))
    if mod == "cidr":
        try:
            net = ipaddress.ip_network(str(expected), strict=False)
        except ValueError as exc:
            raise MatcherError(f"invalid CIDR {expected!r}") from exc

        def in_net(actual: Any) -> bool:
            try:
                return ipaddress.ip_address(str(actual)) in net
            except ValueError:
                return False
        return in_net

    want = str(expected).lower()
    if mod == "contains":
        return lambda a: a is not None and want in str(a).lower()
    if mod == "startswith":
        return lambda a: a is not None and str(a).lower().startswith(want)
    if mod == "endswith":
        return lambda a: a is not None and str(a).lower().endswith(want)
    if "*" in want or "?" in want:  # Sigma wildcards on plain matches
        pattern = re.compile(
            "^" + "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in want) + "$",
            re.DOTALL,
        )
        return lambda a: a is not None and bool(pattern.match(str(a).lower()))
    return lambda a: a is not None and str(a).lower() == want


class FieldMatcher:
    """One ``field|modifier: value(s)`` entry of a selection."""

    def __init__(self, key: str, expected: Any):
        field, *mods = key.split("|")
        unknown = set(mods) - MATCH_MODIFIERS - OTHER_MODIFIERS
        if unknown or len(set(mods) & MATCH_MODIFIERS) > 1:
            raise MatcherError(f"unsupported modifier(s) in {key!r}")
        self.field = field
        self.require_all = "all" in mods
        match_mod = next((m for m in mods if m in MATCH_MODIFIERS), None)
        values = expected if isinstance(expected, list) else [expected]
        if not values:
            raise MatcherError(f"empty value list for {key!r}")
        self._tests = [_value_matcher(match_mod, v) for v in values]

    def matches(self, event: dict) -> bool:
        actual = get_field(event, self.field)
        outcomes = (t(actual) for t in self._tests)
        return all(outcomes) if self.require_all else any(outcomes)


class Selection:
    """A named selection: a map (AND of fields) or a list of maps (OR)."""

    def __init__(self, spec: Any):
        maps = spec if isinstance(spec, list) else [spec]
        if not maps or not all(isinstance(m, dict) and m for m in maps):
            raise MatcherError("selection must be a non-empty mapping or list of mappings")
        self._alternatives = [[FieldMatcher(k, v) for k, v in m.items()] for m in maps]

    def matches(self, event: dict) -> bool:
        return any(all(f.matches(event) for f in alt) for alt in self._alternatives)
