"""Field-level matching with Sigma value-modifier semantics.

Supported modifiers: ``contains``, ``startswith``, ``endswith``, ``re``,
``all``, ``cidr``, ``windash`` and ``exists``. Plain string values support
Sigma wildcards (``*`` and ``?``, escapable with a backslash) and, like
Sigma, compare case-insensitively.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cidr", "windash", "exists"}
_TRANSFORM_MODIFIERS = {"contains", "startswith", "endswith"}


class RuleSyntaxError(ValueError):
    """Raised when a rule's detection block cannot be compiled."""


def sigma_to_regex(value: str) -> str:
    """Translate a Sigma wildcard string into an (unanchored) regex body.

    ``*`` -> ``.*`` and ``?`` -> ``.``; a backslash escapes ``*``, ``?`` or
    another backslash. Any other backslash is literal, which keeps Windows
    paths like ``C:\\Windows\\System32`` readable in rules.
    """
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
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


@lru_cache(maxsize=4096)
def _compile(pattern: str, flags: int) -> re.Pattern[str]:
    return re.compile(pattern, flags)


def _windash_variants(value: str) -> list[str]:
    """Expand ``-flag`` into the dash/slash variants Windows CLIs accept."""
    variants = {value}
    for dash in ("-", "/", "\u2013", "\u2014", "\u2015"):
        variants.add(re.sub(r"(?<=\s)-|^-", dash, value))
    return sorted(variants)


@dataclass
class FieldMatcher:
    """One ``Field|mod1|mod2: value(s)`` entry from a detection selection."""

    field: str
    modifiers: list[str]
    values: list[Any]
    _patterns: list[Any] = field(default_factory=list, repr=False)

    @classmethod
    def parse(cls, key: str, raw_values: Any) -> "FieldMatcher":
        parts = key.split("|")
        name, mods = parts[0], [m.strip().lower() for m in parts[1:]]
        unknown = [m for m in mods if m not in SUPPORTED_MODIFIERS]
        if unknown:
            raise RuleSyntaxError(f"unsupported modifier(s) {unknown} on field '{name}'")
        if len([m for m in mods if m in _TRANSFORM_MODIFIERS]) > 1:
            raise RuleSyntaxError(f"field '{name}' combines mutually exclusive modifiers {mods}")
        if "re" in mods and set(mods) & _TRANSFORM_MODIFIERS:
            raise RuleSyntaxError(f"field '{name}': 're' cannot be combined with {mods}")
        values = raw_values if isinstance(raw_values, list) else [raw_values]
        if not values:
            raise RuleSyntaxError(f"field '{name}' has an empty value list")
        matcher = cls(field=name, modifiers=mods, values=values)
        matcher._prepare()
        return matcher

    def _prepare(self) -> None:
        mods = self.modifiers
        if "exists" in mods:
            if len(self.values) != 1 or not isinstance(self.values[0], bool):
                raise RuleSyntaxError(f"field '{self.field}|exists' needs a single true/false value")
            return
        for value in self.values:
            if value is None:
                self._patterns.append(None)
                continue
            if "cidr" in mods:
                try:
                    self._patterns.append(ipaddress.ip_network(str(value), strict=False))
                except ValueError as exc:
                    raise RuleSyntaxError(f"field '{self.field}': invalid CIDR {value!r}") from exc
                continue
            if "re" in mods:
                try:
                    self._patterns.append(_compile(str(value), 0))
                except re.error as exc:
                    raise RuleSyntaxError(f"field '{self.field}': invalid regex {value!r}: {exc}") from exc
                continue
            raw = str(value)
            candidates = _windash_variants(raw) if "windash" in mods else [raw]
            bodies = [sigma_to_regex(c) for c in candidates]
            body = "(?:" + "|".join(bodies) + ")"
            if "contains" in mods:
                body = f".*{body}.*"
            elif "startswith" in mods:
                body = f"{body}.*"
            elif "endswith" in mods:
                body = f".*{body}"
            self._patterns.append(_compile(body, re.IGNORECASE | re.DOTALL))

    def matches(self, event: dict[str, Any]) -> bool:
        present, actual = lookup(event, self.field)
        if "exists" in self.modifiers:
            return present == self.values[0]
        results = (self._match_one(actual, present, pattern) for pattern in self._patterns)
        return all(results) if "all" in self.modifiers else any(results)

    def _match_one(self, actual: Any, present: bool, pattern: Any) -> bool:
        if pattern is None:  # `Field: null` means "absent or empty"
            return not present or actual in (None, "")
        if not present or actual is None:
            return False
        if isinstance(actual, list):
            return any(self._match_one(item, True, pattern) for item in actual)
        if isinstance(pattern, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            try:
                return ipaddress.ip_address(str(actual)) in pattern
            except ValueError:
                return False
        if isinstance(actual, bool):
            actual = str(actual).lower()
        if "re" in self.modifiers:
            return pattern.search(str(actual)) is not None
        return pattern.fullmatch(str(actual)) is not None


def lookup(event: dict[str, Any], field_name: str) -> tuple[bool, Any]:
    """Find a field by exact key, then by dotted path into nested dicts."""
    if field_name in event:
        return True, event[field_name]
    node: Any = event
    for part in field_name.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return False, None
    return True, node


def iter_string_values(event: Any):
    """Yield every scalar value in an event (used for keyword searches)."""
    if isinstance(event, dict):
        for value in event.values():
            yield from iter_string_values(value)
    elif isinstance(event, list):
        for value in event:
            yield from iter_string_values(value)
    elif event is not None:
        yield str(event)


@dataclass
class Selection:
    """A named detection item: a field map, a list of field maps, or keywords."""

    name: str
    groups: list[list[FieldMatcher]]  # OR of AND-groups
    keywords: list[re.Pattern[str]]

    @classmethod
    def parse(cls, name: str, body: Any) -> "Selection":
        groups: list[list[FieldMatcher]] = []
        keywords: list[re.Pattern[str]] = []
        items = body if isinstance(body, list) else [body]
        if not items:
            raise RuleSyntaxError(f"selection '{name}' is empty")
        for item in items:
            if isinstance(item, dict):
                if not item:
                    raise RuleSyntaxError(f"selection '{name}' contains an empty map")
                groups.append([FieldMatcher.parse(str(k), v) for k, v in item.items()])
            elif isinstance(item, (str, int, float)):
                keywords.append(_compile(f".*{sigma_to_regex(str(item))}.*", re.IGNORECASE | re.DOTALL))
            else:
                raise RuleSyntaxError(f"selection '{name}' has unsupported item {item!r}")
        return cls(name=name, groups=groups, keywords=keywords)

    def matches(self, event: dict[str, Any]) -> bool:
        for group in self.groups:
            if all(m.matches(event) for m in group):
                return True
        if self.keywords:
            values = list(iter_string_values(event))
            return any(kw.fullmatch(v) for kw in self.keywords for v in values)
        return False
