"""Field matching with Sigma value modifiers.

Supported modifiers: contains, startswith, endswith, re, all, cidr, lt/lte/gt/gte.
Plain matches are case-insensitive, as in Sigma. Wildcards ``*`` and ``?``
are honoured in unmodified string values.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from functools import lru_cache
from typing import Any

from .condition import evaluate
from .rule import Rule

_MODS = {"contains", "startswith", "endswith", "re", "all", "cidr", "lt", "lte", "gt", "gte"}


@lru_cache(maxsize=1024)
def _regex(p: str) -> re.Pattern:
    return re.compile(p, re.I)


def _get(event: dict, field: str) -> Any:
    """Look up a field, supporting dotted paths into nested dicts."""
    if field in event:
        return event[field]
    cur: Any = event
    for part in field.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _match_one(value: Any, expected: Any, mods: list[str]) -> bool:
    if expected is None:
        return value is None
    if value is None:
        return False
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(value)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    for op, fn in (("lt", lambda a, b: a < b), ("lte", lambda a, b: a <= b),
                   ("gt", lambda a, b: a > b), ("gte", lambda a, b: a >= b)):
        if op in mods:
            try:
                return fn(float(value), float(expected))
            except (TypeError, ValueError):
                return False
    if isinstance(expected, (int, float, bool)) and not isinstance(value, str):
        return value == expected
    v, e = str(value), str(expected)
    if "re" in mods:
        return _regex(e).search(v) is not None
    vl, el = v.lower(), e.lower()
    if "contains" in mods:
        return el in vl
    if "startswith" in mods:
        return vl.startswith(el)
    if "endswith" in mods:
        return vl.endswith(el)
    if "*" in el or "?" in el:
        return fnmatch.fnmatchcase(vl, el)
    return vl == el


def _match_field(event: dict, key: str, expected: Any) -> bool:
    name, *mods = key.split("|")
    bad = set(mods) - _MODS
    if bad:
        raise ValueError(f"unsupported modifier(s) {sorted(bad)} in {key!r}")
    value = _get(event, name)
    values = value if isinstance(value, list) else [value]
    exp = expected if isinstance(expected, list) else [expected]
    if "all" in mods:
        return all(any(_match_one(v, e, mods) for v in values) for e in exp)
    return any(_match_one(v, e, mods) for v in values for e in exp)


def _match_selection(event: dict, sel: Any) -> bool:
    """A mapping is an AND of fields; a list of mappings is an OR of those."""
    if isinstance(sel, dict):
        return all(_match_field(event, k, v) for k, v in sel.items())
    if isinstance(sel, list):
        if all(isinstance(s, dict) for s in sel):
            return any(_match_selection(event, s) for s in sel)
        # list of plain strings: keyword search across all values
        blob = " ".join(str(v) for v in event.values()).lower()
        return any(str(s).lower() in blob for s in sel)
    raise ValueError(f"bad selection: {sel!r}")


def matches(rule: Rule, event: dict) -> bool:
    sels = {n: (lambda s=s: _match_selection(event, s)) for n, s in rule.detection.items()}
    return evaluate(rule.ast, sels)
