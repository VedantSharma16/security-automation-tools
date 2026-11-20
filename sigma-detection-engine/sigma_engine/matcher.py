"""Compilation of Sigma detection identifiers into event-matching predicates.

Supported semantics (a pragmatic subset of the Sigma specification):

* **Maps** - every field must match (AND).
* **Lists of maps** - any map may match (OR).
* **Lists of values** for one field - any value may match (OR) unless the
  ``|all`` modifier is used.
* **Plain lists of strings** (no field) - keyword search over every string
  value in the event.
* **Wildcards** - ``*`` and ``?`` in plain values; ``\\*`` escapes them.
* String matching is **case-insensitive**, except for ``|re``.
* ``null`` matches a missing or null field.

Value modifiers: ``contains``, ``startswith``, ``endswith``, ``all``, ``re``,
``cidr``, ``base64``, ``windash``, ``exists``, ``gt``, ``gte``, ``lt``, ``lte``.
Nested fields can be addressed with dots (``process.parent.name``).
"""

from __future__ import annotations

import base64
import ipaddress
import re
from typing import Any, Callable, Mapping

__all__ = ["MatcherError", "compile_detection_item", "get_field", "SUPPORTED_MODIFIERS"]

Predicate = Callable[[Mapping[str, Any]], bool]

SUPPORTED_MODIFIERS = frozenset(
    {
        "contains", "startswith", "endswith", "all", "re", "cidr", "base64",
        "windash", "exists", "gt", "gte", "lt", "lte",
    }
)
_POSITION_MODIFIERS = {"contains", "startswith", "endswith"}
_NUMERIC_MODIFIERS = {"gt", "gte", "lt", "lte"}
_MISSING = object()


class MatcherError(ValueError):
    """Raised when a detection item cannot be compiled."""


# ----------------------------------------------------------------- field access


def get_field(event: Mapping[str, Any], name: str) -> Any:
    """Look up ``name`` in ``event``; dotted names walk nested dicts.

    An exact key match wins over nested traversal so flat keys that happen
    to contain dots (common in ECS-flattened logs) still work.
    """
    if name in event:
        return event[name]
    current: Any = event
    for part in name.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _iter_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_strings(v)
    elif value is not None and not isinstance(value, bool):
        yield str(value)


# --------------------------------------------------------------- value patterns


def _wildcard_body(pattern: str) -> str:
    """Translate a Sigma value with ``*``/``?`` wildcards into a regex body.

    ``\\*``, ``\\?`` and ``\\\\`` are escapes for the literal characters; any
    other backslash is literal (so Windows paths need no escaping).
    """
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def _wildcard_to_regex(pattern: str, prefix_any: bool = False, suffix_any: bool = False) -> re.Pattern:
    # Modifier wildcards are added at the regex level, *after* escape handling,
    # so a value ending in a backslash (``\AppData\``) can't accidentally
    # escape the ``*`` that ``contains`` appends.
    body = ("(?:.*)" if prefix_any else "") + _wildcard_body(pattern) + ("(?:.*)" if suffix_any else "")
    return re.compile(f"^{body}$", re.IGNORECASE | re.DOTALL)


def _windash_variants(value: str) -> list[str]:
    """Expand ``-flag`` to its Windows alternatives (``/flag``, en/em dash)."""
    variants = {value}
    for repl in ("/", "–", "—", "―"):
        variants.add(re.sub(r"(^|\s)-", lambda m: m.group(1) + repl, value))
    return sorted(variants)


def _to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _compile_value(value: Any, modifiers: list[str]) -> Callable[[Any], bool]:
    """Compile one expected value + modifier chain into ``f(actual) -> bool``."""
    mods = set(modifiers)

    if value is None:
        return lambda actual: actual is _MISSING or actual is None

    if "exists" in mods:
        if not isinstance(value, bool):
            raise MatcherError("'exists' modifier requires a boolean value")
        return lambda actual: (actual is not _MISSING and actual is not None) == value

    if mods & _NUMERIC_MODIFIERS:
        (op,) = mods & _NUMERIC_MODIFIERS
        target = _to_number(value)
        if target is None:
            raise MatcherError(f"'{op}' modifier requires a numeric value, got {value!r}")
        compare = {
            "gt": lambda a: a > target,
            "gte": lambda a: a >= target,
            "lt": lambda a: a < target,
            "lte": lambda a: a <= target,
        }[op]

        def numeric(actual: Any) -> bool:
            n = _to_number(actual)
            return n is not None and compare(n)

        return numeric

    if "cidr" in mods:
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError as exc:
            raise MatcherError(f"invalid CIDR {value!r}: {exc}") from None

        def in_network(actual: Any) -> bool:
            try:
                return ipaddress.ip_address(str(actual)) in network
            except ValueError:
                return False

        return in_network

    if "re" in mods:
        try:
            regex = re.compile(str(value))
        except re.error as exc:
            raise MatcherError(f"invalid regex {value!r}: {exc}") from None
        return lambda actual: actual is not _MISSING and actual is not None and bool(
            regex.search(str(actual))
        )

    # --- plain / wildcard string matching ---------------------------------
    if isinstance(value, bool):
        return lambda actual: actual == value
    text = str(value)
    if "base64" in mods:
        text = base64.b64encode(text.encode()).decode()
    texts = _windash_variants(text) if "windash" in mods else [text]

    prefix_any = "contains" in mods or "endswith" in mods
    suffix_any = "contains" in mods or "startswith" in mods
    patterns = [_wildcard_to_regex(t, prefix_any, suffix_any) for t in texts]

    def string_match(actual: Any) -> bool:
        if actual is _MISSING or actual is None:
            return False
        candidates = actual if isinstance(actual, list) else [actual]
        for cand in candidates:
            s = str(cand).lower() if isinstance(cand, bool) else str(cand)
            if any(p.match(s) for p in patterns):
                return True
        return False

    return string_match


# ----------------------------------------------------------- detection items


def _compile_field(spec: str, expected: Any) -> Predicate:
    field, *modifiers = spec.split("|")
    unknown = [m for m in modifiers if m not in SUPPORTED_MODIFIERS]
    if unknown:
        raise MatcherError(f"unsupported modifier(s) {unknown} on field {field!r}")
    if len(set(modifiers) & (_POSITION_MODIFIERS | {"re", "cidr"} | _NUMERIC_MODIFIERS)) > 1:
        raise MatcherError(f"conflicting modifiers {modifiers} on field {field!r}")

    values = expected if isinstance(expected, list) else [expected]
    if not values:
        raise MatcherError(f"field {field!r} has an empty value list")
    checks = [_compile_value(v, modifiers) for v in values]
    require_all = "all" in modifiers

    def predicate(event: Mapping[str, Any]) -> bool:
        actual = get_field(event, field)
        results = (c(actual) for c in checks)
        return all(results) if require_all else any(results)

    return predicate


def _compile_map(item: Mapping[str, Any]) -> Predicate:
    if not item:
        raise MatcherError("empty field map")
    preds = [_compile_field(str(k), v) for k, v in item.items()]
    return lambda event: all(p(event) for p in preds)


def _compile_keywords(keywords: list[Any]) -> Predicate:
    patterns = [_wildcard_to_regex(str(k), True, True) for k in keywords]

    def predicate(event: Mapping[str, Any]) -> bool:
        return any(p.match(s) for s in _iter_strings(event) for p in patterns)

    return predicate


def compile_detection_item(item: Any) -> Predicate:
    """Compile the value of one detection identifier (e.g. ``selection``)."""
    if isinstance(item, Mapping):
        return _compile_map(item)
    if isinstance(item, list):
        if not item:
            raise MatcherError("empty detection list")
        if all(isinstance(x, Mapping) for x in item):
            preds = [_compile_map(x) for x in item]
            return lambda event: any(p(event) for p in preds)
        if all(not isinstance(x, (Mapping, list)) for x in item):
            return _compile_keywords(item)
        raise MatcherError("detection list mixes field maps and keywords")
    if isinstance(item, (str, int, float)):
        return _compile_keywords([item])
    raise MatcherError(f"unsupported detection item type {type(item).__name__}")
