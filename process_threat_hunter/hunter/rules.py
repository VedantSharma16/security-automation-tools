"""Loading and representing detection rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

VALID_MATCH_FIELDS = {"name", "exe", "cmdline"}


class RuleValidationError(ValueError):
    """Raised when a rule definition is malformed."""


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern
    match_fields: tuple
    severity: str
    mitre_tactic: str
    mitre_technique: str
    description: str
    raw_pattern: str = field(compare=False, default="")

    def matches(self, process) -> tuple:
        """Return (matched_field, matched_text) for the first field that
        matches this rule's pattern, or None if nothing matched."""
        for field_name in self.match_fields:
            value = getattr(process, field_name, None)
            if not value:
                continue
            haystack = value if isinstance(value, str) else " ".join(value)
            m = self.pattern.search(haystack)
            if m:
                return field_name, m.group(0)
        return None


def _compile_rule(raw: dict) -> Rule:
    required = {"id", "pattern", "match_fields", "severity", "mitre_tactic", "mitre_technique"}
    missing = required - raw.keys()
    if missing:
        raise RuleValidationError(f"rule missing required keys: {sorted(missing)}")

    severity = raw["severity"].lower()
    if severity not in SEVERITY_RANK:
        raise RuleValidationError(
            f"rule {raw['id']!r} has invalid severity {severity!r}; "
            f"expected one of {SEVERITIES}"
        )

    match_fields = tuple(raw["match_fields"])
    invalid_fields = set(match_fields) - VALID_MATCH_FIELDS
    if invalid_fields:
        raise RuleValidationError(
            f"rule {raw['id']!r} has invalid match_fields {sorted(invalid_fields)}; "
            f"expected subset of {sorted(VALID_MATCH_FIELDS)}"
        )

    try:
        pattern = re.compile(raw["pattern"], re.IGNORECASE)
    except re.error as exc:
        raise RuleValidationError(f"rule {raw['id']!r} has invalid regex: {exc}") from exc

    return Rule(
        id=raw["id"],
        pattern=pattern,
        match_fields=match_fields,
        severity=severity,
        mitre_tactic=raw["mitre_tactic"],
        mitre_technique=raw["mitre_technique"],
        description=raw.get("description", ""),
        raw_pattern=raw["pattern"],
    )


def load_rules(path) -> list:
    """Load and validate a YAML rule file, returning a list of Rule objects."""
    with open(path, "r", encoding="utf-8") as fh:
        raw_rules = yaml.safe_load(fh) or []

    if not isinstance(raw_rules, list):
        raise RuleValidationError("rule file must contain a YAML list of rules")

    rules = [_compile_rule(raw) for raw in raw_rules]

    ids = [r.id for r in rules]
    duplicates = {rid for rid in ids if ids.count(rid) > 1}
    if duplicates:
        raise RuleValidationError(f"duplicate rule ids: {sorted(duplicates)}")

    return rules
