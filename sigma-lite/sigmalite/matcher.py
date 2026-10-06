"""Field matching with Sigma-style modifiers (``field|contains|all`` ...)."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

VALUE_MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "lt", "lte", "gt", "gte"}
COMBINERS = {"all"}
KNOWN_MODIFIERS = VALUE_MODIFIERS | COMBINERS


class MatchError(ValueError):
    pass


def split_key(key: str) -> tuple[str, list[str]]:
    field, *mods = key.split("|")
    if not field:
        raise MatchError(f"empty field name in {key!r}")
    for m in mods:
        if m not in KNOWN_MODIFIERS:
            raise MatchError(f"unknown modifier {m!r} in {key!r}")
    if len([m for m in mods if m in VALUE_MODIFIERS]) > 1:
        raise MatchError(f"multiple match modifiers in {key!r}")
    return field, mods


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


def _one(actual: Any, mod: str | None, expected: Any) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    if mod in ("lt", "lte", "gt", "gte"):
        try:
            a, e = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"lt": a < e, "lte": a <= e, "gt": a > e, "gte": a >= e}[mod]
    if mod == "cidr":
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    a = str(actual).lower()
    if mod == "re":
        return re.search(str(expected), str(actual), re.IGNORECASE) is not None
    e = str(expected).lower()
    if mod == "contains":
        return e in a
    if mod == "startswith":
        return a.startswith(e)
    if mod == "endswith":
        return a.endswith(e)
    # Plain equality is case-insensitive, with * and ? wildcards.
    if "*" in e or "?" in e:
        pattern = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in e)
        return re.fullmatch(pattern, a, re.DOTALL) is not None
    return a == e


def match_field(event: dict, key: str, expected: Any) -> bool:
    """Match one ``key: value(s)`` pair. Lists are OR'd unless ``|all``."""
    field, mods = split_key(key)
    mod = next((m for m in mods if m in VALUE_MODIFIERS), None)
    actual = _get(event, field)
    values = expected if isinstance(expected, list) else [expected]
    if not values:
        return False
    check = all if "all" in mods else any
    return check(_one(actual, mod, v) for v in values)


def match_selection(event: dict, selection: Any) -> bool:
    """A selection is a dict (AND of fields) or a list of dicts (OR)."""
    if isinstance(selection, list):
        return any(match_selection(event, s) for s in selection)
    if not isinstance(selection, dict) or not selection:
        raise MatchError("selection must be a non-empty mapping or list of mappings")
    return all(match_field(event, k, v) for k, v in selection.items())
