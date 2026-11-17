"""Compile Sigma ``detection`` selections into fast predicate functions.

Semantics follow the Sigma specification:

* A selection that is a **mapping** ANDs its fields together; a list value
  for one field ORs the alternatives (unless the ``|all`` modifier is used).
* A selection that is a **list of mappings** ORs the mappings.
* A selection that is a **list of strings** is a keyword search across every
  string value in the event.
* Plain string comparison is **case-insensitive** and supports ``*`` / ``?``
  wildcards (escape with ``\\``). ``|re`` is case-sensitive unless the
  pattern itself says otherwise (e.g. ``(?i)``).
* ``null`` matches a missing or null field.

Supported modifiers: ``contains``, ``startswith``, ``endswith``, ``all``,
``re``, ``cidr``, ``exists``, ``windash``, ``gt``/``gte``/``lt``/``lte``,
``base64``.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from typing import Any, Callable, Iterable, Mapping

Event = Mapping[str, Any]
Predicate = Callable[[Event], bool]
ValuePredicate = Callable[[Any], bool]

SUPPORTED_MODIFIERS = {
    "contains", "startswith", "endswith", "all", "re", "cidr", "exists",
    "windash", "gt", "gte", "lt", "lte", "base64",
}
_MISSING = object()


class MatcherError(ValueError):
    """Raised for malformed selections or unsupported modifiers."""


# --------------------------------------------------------------------------- field access


def get_field(event: Event, path: str, field_map: Mapping[str, str] | None = None) -> Any:
    """Resolve ``path`` in ``event``.

    An exact key wins; otherwise a dotted path walks nested mappings, so
    both flat Sysmon-style events and nested ECS-style events work. A
    ``field_map`` translates Sigma field names to the log's own schema.
    """
    if field_map and path in field_map:
        path = field_map[path]
    if path in event:
        return event[path]
    cur: Any = event
    for part in path.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _iter_strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, Mapping):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_strings(v)
    elif obj is not None and not isinstance(obj, bool):
        yield str(obj)


# --------------------------------------------------------------------------- value matchers


def _wildcard_to_regex(pattern: str) -> str:
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return "".join(out)


def _windash_variants(value: str) -> list[str]:
    """Expand ``-flag`` into the dash variants Windows CLIs accept."""
    dashes = ["-", "/", "–", "—", "―"]
    variants = {value}
    for d in dashes[1:]:
        variants.add(re.sub(r"(^|\s)-", lambda m: m.group(1) + d, value))
    return sorted(variants)


def _string_matcher(value: str, mode: str) -> ValuePredicate:
    if mode == "re":
        rx = re.compile(value)
        return lambda v: isinstance(v, (str, int, float)) and bool(rx.search(str(v)))
    body = _wildcard_to_regex(value)
    if mode == "contains":
        body = f".*{body}.*"
    elif mode == "startswith":
        body = f"{body}.*"
    elif mode == "endswith":
        body = f".*{body}"
    rx = re.compile(f"^{body}$", re.IGNORECASE | re.DOTALL)

    def match(v: Any) -> bool:
        if v is None or isinstance(v, (Mapping, list, tuple)):
            return False
        if isinstance(v, bool):
            v = str(v).lower()
        return bool(rx.match(str(v)))

    return match


def _numeric_matcher(value: Any, op: str) -> ValuePredicate:
    try:
        ref = float(value)
    except (TypeError, ValueError) as exc:
        raise MatcherError(f"|{op} requires a numeric value, got {value!r}") from exc
    ops = {
        "gt": lambda a: a > ref, "gte": lambda a: a >= ref,
        "lt": lambda a: a < ref, "lte": lambda a: a <= ref,
    }

    def match(v: Any) -> bool:
        try:
            return ops[op](float(v))
        except (TypeError, ValueError):
            return False

    return match


def _cidr_matcher(value: str) -> ValuePredicate:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise MatcherError(f"invalid CIDR {value!r}") from exc

    def match(v: Any) -> bool:
        try:
            return ipaddress.ip_address(str(v)) in net
        except ValueError:
            return False

    return match


def _value_matcher(value: Any, modifiers: list[str]) -> ValuePredicate:
    """Build a predicate for one expected value under the given modifiers."""
    if value is None:
        return lambda v: v is None or v is _MISSING

    for op in ("gt", "gte", "lt", "lte"):
        if op in modifiers:
            return _numeric_matcher(value, op)
    if "cidr" in modifiers:
        return _cidr_matcher(str(value))

    if isinstance(value, bool):
        return lambda v: v is value or (isinstance(v, str) and v.lower() == str(value).lower())
    if isinstance(value, (int, float)):
        s = _string_matcher(str(value), "exact")
        return lambda v: (not isinstance(v, bool) and isinstance(v, (int, float)) and v == value) or s(v)

    text = str(value)
    if "base64" in modifiers:
        text = base64.b64encode(text.encode()).decode()
        if ("contains" in modifiers or "startswith" in modifiers) and text.endswith("="):
            # When the input length isn't a multiple of 3, the last encoded
            # character mixes in bits from whatever *follows* the needle in a
            # longer payload, and the '=' padding won't be there at all. Drop
            # both so the needle matches as a prefix/substring.
            text = text.rstrip("=")[:-1]

    mode = "exact"
    for m in ("re", "contains", "startswith", "endswith"):
        if m in modifiers:
            mode = m
            break

    if "windash" in modifiers:
        preds = [_string_matcher(v, mode) for v in _windash_variants(text)]
        return lambda v: any(p(v) for p in preds)
    return _string_matcher(text, mode)


# --------------------------------------------------------------------------- field / selection compile


def _compile_field(key: str, expected: Any, field_map: Mapping[str, str] | None) -> Predicate:
    field, *modifiers = key.split("|")
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise MatcherError(f"unsupported modifier(s) {sorted(unknown)} on field {field!r}")

    if "exists" in modifiers:
        want = bool(expected)
        return lambda e: (get_field(e, field, field_map) is not _MISSING) is want

    values = expected if isinstance(expected, list) else [expected]
    if not values:
        raise MatcherError(f"field {field!r} has an empty value list")
    preds = [_value_matcher(v, modifiers) for v in values]
    combine = all if "all" in modifiers else any

    def match(event: Event) -> bool:
        actual = get_field(event, field, field_map)
        if actual is _MISSING:
            # Only an explicit `null` expectation can match a missing field.
            return combine(v is None for v in values)
        candidates = actual if isinstance(actual, list) else [actual]
        return combine(any(p(c) for c in candidates) for p in preds)

    return match


def _compile_mapping(mapping: Mapping[str, Any], field_map: Mapping[str, str] | None) -> Predicate:
    if not mapping:
        raise MatcherError("empty selection mapping")
    preds = [_compile_field(str(k), v, field_map) for k, v in mapping.items()]
    return lambda e: all(p(e) for p in preds)


def compile_selection(selection: Any, field_map: Mapping[str, str] | None = None) -> Predicate:
    """Compile one named selection (mapping, list of mappings, or keyword list)."""
    if isinstance(selection, Mapping):
        return _compile_mapping(selection, field_map)
    if isinstance(selection, list) and selection:
        if all(isinstance(s, Mapping) for s in selection):
            preds = [_compile_mapping(s, field_map) for s in selection]
            return lambda e: any(p(e) for p in preds)
        if all(isinstance(s, (str, int, float)) for s in selection):
            kw = [_string_matcher(str(s), "contains") for s in selection]
            return lambda e: any(p(v) for v in _iter_strings(e) for p in kw)
    raise MatcherError(f"unsupported selection shape: {selection!r}")
