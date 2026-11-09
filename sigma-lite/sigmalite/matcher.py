"""Field matching with Sigma value modifiers (contains, startswith, endswith, re, all, cidr)."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable, Mapping

MAX_REGEX_LEN = 500  # crude guard: rules are trusted-ish, but keep patterns bounded
SUPPORTED = {"contains", "startswith", "endswith", "re", "all", "cidr"}


class MatcherError(ValueError):
    pass


def _norm(v: Any) -> str:
    return str(v).lower()


def _make_pred(mod: str | None, value: Any) -> Callable[[Any], bool]:
    if value is None:
        return lambda ev: ev is None
    if mod == "re":
        if len(str(value)) > MAX_REGEX_LEN:
            raise MatcherError("regex too long")
        try:
            rx = re.compile(str(value), re.IGNORECASE)
        except re.error as e:
            raise MatcherError(f"invalid regex {value!r}: {e}") from e
        return lambda ev: ev is not None and rx.search(str(ev)) is not None
    if mod == "cidr":
        try:
            net = ipaddress.ip_network(str(value), strict=False)
        except ValueError as e:
            raise MatcherError(str(e)) from e

        def cidr(ev):
            try:
                return ipaddress.ip_address(str(ev)) in net
            except ValueError:
                return False
        return cidr
    v = _norm(value)
    if mod == "contains":
        return lambda ev: ev is not None and v in _norm(ev)
    if mod == "startswith":
        return lambda ev: ev is not None and _norm(ev).startswith(v)
    if mod == "endswith":
        return lambda ev: ev is not None and _norm(ev).endswith(v)
    if "*" in v or "?" in v:  # Sigma wildcards on plain equality
        rx = re.compile("^" + "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in v) + "$", re.S)
        return lambda ev: ev is not None and rx.match(_norm(ev)) is not None
    return lambda ev: ev is not None and _norm(ev) == v


class FieldMatcher:
    """One ``field|mod1|mod2: value(s)`` entry of a selection."""

    def __init__(self, key: str, expected: Any):
        field, *mods = key.split("|")
        bad = [m for m in mods if m not in SUPPORTED]
        if bad:
            raise MatcherError(f"unsupported modifier(s) {bad} in {key!r}")
        self.field = field
        self.require_all = "all" in mods
        kind = next((m for m in mods if m != "all"), None)
        values = expected if isinstance(expected, list) else [expected]
        if not values:
            raise MatcherError(f"empty value list for {key!r}")
        self.preds = [_make_pred(kind, v) for v in values]

    def matches(self, event: Mapping[str, Any]) -> bool:
        actual = get_field(event, self.field)
        results = (p(actual) for p in self.preds)
        return all(results) if self.require_all else any(results)


def get_field(event: Mapping[str, Any], path: str) -> Any:
    """Case-insensitive lookup; supports dotted paths into nested dicts."""
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, Mapping):
            return None
        if part in cur:
            cur = cur[part]
        else:
            low = part.lower()
            hit = next((k for k in cur if str(k).lower() == low), None)
            if hit is None:
                return None
            cur = cur[hit]
    return cur


class Selection:
    """Either a field-map (AND of FieldMatchers) or a keyword list (substring anywhere)."""

    def __init__(self, spec: Any):
        self.keywords: list[str] = []
        self.matchers: list[FieldMatcher] = []
        if isinstance(spec, dict):
            self.matchers = [FieldMatcher(k, v) for k, v in spec.items()]
        elif isinstance(spec, list) and all(isinstance(x, dict) for x in spec):
            # list of maps => OR of maps
            self.alternatives = [Selection(x) for x in spec]
            return
        elif isinstance(spec, list):
            self.keywords = [_norm(x) for x in spec]
        else:
            raise MatcherError("selection must be a map or list")
        self.alternatives = []
        if not self.matchers and not self.keywords:
            raise MatcherError("empty selection")

    def matches(self, event: Mapping[str, Any]) -> bool:
        if self.alternatives:
            return any(a.matches(event) for a in self.alternatives)
        if self.keywords:
            blob = " ".join(_norm(v) for v in _flatten(event))
            return any(k in blob for k in self.keywords)
        return all(m.matches(event) for m in self.matchers)


def _flatten(obj: Any):
    if isinstance(obj, Mapping):
        for v in obj.values():
            yield from _flatten(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _flatten(v)
    elif obj is not None:
        yield obj
