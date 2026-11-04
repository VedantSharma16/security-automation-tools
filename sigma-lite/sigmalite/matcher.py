"""Field matching with Sigma value modifiers (contains, startswith, endswith, re, all, cidr)."""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from typing import Any, Callable

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cidr", "lt", "lte", "gt", "gte"}
_MAX_PATTERN_LEN = 500


class ModifierError(ValueError):
    pass


def get_field(event: dict, name: str) -> Any:
    """Look up a field; supports flat keys with dots and nested dict traversal."""
    if name in event:
        return event[name]
    cur: Any = event
    for part in name.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _wildcard_to_regex(pattern: str) -> re.Pattern:
    # Sigma wildcards: * and ?, with backslash escaping. Case-insensitive.
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


def _single(modifiers: list[str], expected: Any) -> Callable[[Any], bool]:
    """Build a predicate for one expected value."""
    if expected is None:
        return lambda actual: actual is None
    mods = [m for m in modifiers if m not in ("all",)]
    if len(mods) > 1:
        raise ModifierError(f"only one comparison modifier allowed, got {mods}")
    mod = mods[0] if mods else None

    if mod in ("lt", "lte", "gt", "gte"):
        try:
            num = float(expected)
        except (TypeError, ValueError):
            raise ModifierError(f"modifier '{mod}' needs a numeric value, got {expected!r}")
        ops = {"lt": float.__lt__, "lte": float.__le__, "gt": float.__gt__, "gte": float.__ge__}

        def numeric(actual: Any) -> bool:
            try:
                return ops[mod](float(actual), num)
            except (TypeError, ValueError):
                return False
        return numeric

    if mod == "cidr":
        try:
            net = ipaddress.ip_network(str(expected), strict=False)
        except ValueError as exc:
            raise ModifierError(f"invalid CIDR {expected!r}: {exc}")

        def in_net(actual: Any) -> bool:
            try:
                return ipaddress.ip_address(str(actual)) in net
            except ValueError:
                return False
        return in_net

    if mod == "re":
        if len(str(expected)) > _MAX_PATTERN_LEN:
            raise ModifierError("regex too long")
        try:
            rx = re.compile(str(expected), re.IGNORECASE)
        except re.error as exc:
            raise ModifierError(f"invalid regex {expected!r}: {exc}")
        return lambda actual: actual is not None and rx.search(str(actual)) is not None

    exp = str(expected)
    if mod == "contains":
        exp_l = exp.lower()
        return lambda a: a is not None and exp_l in str(a).lower()
    if mod == "startswith":
        exp_l = exp.lower()
        return lambda a: a is not None and str(a).lower().startswith(exp_l)
    if mod == "endswith":
        exp_l = exp.lower()
        return lambda a: a is not None and str(a).lower().endswith(exp_l)

    if isinstance(expected, bool) or isinstance(expected, (int, float)):
        return lambda a: a is not None and str(a).lower() == str(expected).lower()
    if "*" in exp or "?" in exp:
        rx = _wildcard_to_regex(exp)
        return lambda a: a is not None and rx.match(str(a)) is not None
    exp_l = exp.lower()
    return lambda a: a is not None and str(a).lower() == exp_l


def compile_field(key: str, expected: Any) -> Callable[[dict], bool]:
    """Compile a detection item like ``CommandLine|contains|all: [a, b]`` into a predicate."""
    field, *modifiers = key.split("|")
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise ModifierError(f"unsupported modifier(s) {sorted(unknown)} in '{key}'")
    values = expected if isinstance(expected, list) else [expected]
    if not values:
        raise ModifierError(f"empty value list for '{key}'")
    preds = [_single(modifiers, v) for v in values]
    combine = all if "all" in modifiers else any

    def check(event: dict) -> bool:
        actual = get_field(event, field)
        if isinstance(actual, list):  # any element of a list-valued field may match
            return any(combine(p(a) for p in preds) for a in actual)
        return combine(p(actual) for p in preds)

    return check


def compile_selection(selection: Any) -> Callable[[dict], bool]:
    """A selection is a map (AND of fields) or a list of maps (OR of maps)."""
    if isinstance(selection, dict):
        checks = [compile_field(k, v) for k, v in selection.items()]
        if not checks:
            raise ModifierError("empty selection")
        return lambda ev: all(c(ev) for c in checks)
    if isinstance(selection, list) and selection and all(isinstance(s, dict) for s in selection):
        subs = [compile_selection(s) for s in selection]
        return lambda ev: any(s(ev) for s in subs)
    raise ModifierError("selection must be a mapping or a list of mappings")
