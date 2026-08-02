"""Loading and representing regex-based secret-detection rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


class RuleValidationError(ValueError):
    """Raised when a rule definition is malformed."""


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern
    severity: str
    category: str
    description: str
    raw_pattern: str = field(compare=False, default="")

    def search(self, line: str):
        """Return the first regex match of this rule against ``line``, or None."""
        return self.pattern.search(line)


def _compile_rule(raw: dict) -> Rule:
    required = {"id", "pattern", "severity", "category"}
    missing = required - raw.keys()
    if missing:
        raise RuleValidationError(f"rule missing required keys: {sorted(missing)}")

    severity = raw["severity"].lower()
    if severity not in SEVERITY_RANK:
        raise RuleValidationError(
            f"rule {raw['id']!r} has invalid severity {severity!r}; "
            f"expected one of {SEVERITIES}"
        )

    try:
        pattern = re.compile(raw["pattern"])
    except re.error as exc:
        raise RuleValidationError(f"rule {raw['id']!r} has invalid regex: {exc}") from exc

    return Rule(
        id=raw["id"],
        pattern=pattern,
        severity=severity,
        category=raw["category"],
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
