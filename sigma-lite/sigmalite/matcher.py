"""Field matching with Sigma value modifiers.

Supported modifiers: contains, startswith, endswith, all, re, cidr,
gt/gte/lt/lte, base64 (value is base64-encoded before comparison), exists.
Plain values are matched case-insensitively and support ``*`` / ``?`` wildcards.
"""
from __future__ import annotations

import base64
import ipaddress
import re
from typing import Any

MAX_REGEX_LEN = 500


class MatchError(ValueError):
    pass


def get_field(event: dict, name: str) -> Any:
    if name in event:
        return event[name]
    cur: Any = event
    for part in name.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _wildcard_regex(pattern: str) -> re.Pattern:
    out, i = "", 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out += re.escape(pattern[i + 1])
            i += 2
            continue
        out += ".*" if ch == "*" else "." if ch == "?" else re.escape(ch)
        i += 1
    return re.compile(out, re.IGNORECASE | re.DOTALL)


def _one(actual: Any, expected: Any, mods: list[str]) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if actual is None:
        return False
    if "re" in mods:
        pattern = str(expected)
        if len(pattern) > MAX_REGEX_LEN:
            raise MatchError("regex too long")
        return re.search(pattern, str(actual), re.IGNORECASE) is not None
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    for op, fn in (("gte", lambda a, b: a >= b), ("gt", lambda a, b: a > b),
                   ("lte", lambda a, b: a <= b), ("lt", lambda a, b: a < b)):
        if op in mods:
            try:
                return fn(float(actual), float(expected))
            except (TypeError, ValueError):
                return False
    exp = str(expected)
    if "base64" in mods:
        exp = base64.b64encode(exp.encode()).decode()
    act = str(actual)
    if isinstance(expected, bool) or isinstance(actual, bool):
        return act.lower() == exp.lower()
    if "contains" in mods:
        exp = f"*{exp}*"
    elif "startswith" in mods:
        exp = f"{exp}*"
    elif "endswith" in mods:
        exp = f"*{exp}"
    return _wildcard_regex(exp).fullmatch(act) is not None


def match_field(event: dict, key: str, expected: Any) -> bool:
    name, *mods = key.split("|")
    mods = [m.lower() for m in mods]
    actual = get_field(event, name)
    if "exists" in mods:
        return (actual is not None) == bool(expected)
    values = expected if isinstance(expected, list) else [expected]
    if isinstance(actual, list):  # any element of a list-valued field may match
        test = lambda v: any(_one(a, v, mods) for a in actual)
    else:
        test = lambda v: _one(actual, v, mods)
    return all(test(v) for v in values) if "all" in mods else any(test(v) for v in values)


def match_selection(event: dict, selection: Any) -> bool:
    """A mapping is AND of its fields; a list of mappings is OR; a list of
    plain strings is a keyword search over the whole event."""
    if isinstance(selection, dict):
        return all(match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        if all(isinstance(s, dict) for s in selection):
            return any(match_selection(event, s) for s in selection)
        blob = " ".join(str(v) for v in _flatten(event))
        return any(_wildcard_regex(f"*{s}*").fullmatch(blob) for s in map(str, selection))
    raise MatchError(f"unsupported selection type: {type(selection).__name__}")


def _flatten(obj: Any):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _flatten(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _flatten(v)
    else:
        yield obj
