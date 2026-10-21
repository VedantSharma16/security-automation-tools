"""Field matching with Sigma value modifiers (contains, startswith, re, ...)."""
from __future__ import annotations

import fnmatch
import re
from typing import Any

MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cased", "lt", "lte", "gt", "gte"}


def _wildcard_to_regex(pattern: str) -> re.Pattern:
    return re.compile(fnmatch.translate(pattern), re.DOTALL)


def _get(event: dict, field: str) -> Any:
    """Look up a field, supporting dotted paths into nested dicts."""
    if field in event:
        return event[field]
    cur: Any = event
    for part in field.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _match_one(actual: Any, expected: Any, mods: set[str]) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    cased = "cased" in mods
    for op, fn in (("lt", lambda a, b: a < b), ("lte", lambda a, b: a <= b),
                   ("gt", lambda a, b: a > b), ("gte", lambda a, b: a >= b)):
        if op in mods:
            try:
                return fn(float(actual), float(expected))
            except (TypeError, ValueError):
                return False
    if "re" in mods:
        return re.search(str(expected), str(actual)) is not None
    a, e = str(actual), str(expected)
    if not cased:
        a, e = a.lower(), e.lower()
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    if "*" in e or "?" in e:
        return _wildcard_to_regex(e).fullmatch(a) is not None
    return a == e


def match_field(event: dict, key: str, expected: Any) -> bool:
    field, *mod_list = key.split("|")
    mods = set(mod_list)
    unknown = mods - MODIFIERS
    if unknown:
        raise ValueError(f"unknown modifier(s) {sorted(unknown)} in {key!r}")
    actual = _get(event, field)
    values = expected if isinstance(expected, list) else [expected]
    results = (_match_one(actual, v, mods) for v in values)
    return all(results) if "all" in mods else any(results)


def match_selection(event: dict, selection: Any) -> bool:
    """A selection is a map (AND of fields) or a list of maps (OR)."""
    if isinstance(selection, list):
        return any(match_selection(event, s) for s in selection)
    if isinstance(selection, dict):
        return all(match_field(event, k, v) for k, v in selection.items())
    raise ValueError(f"selection must be a mapping or list of mappings, got {type(selection).__name__}")
