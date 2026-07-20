"""Loading and representing secret-detection signatures."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import entropy as entropy_mod

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
    entropy_check: bool = False
    raw_pattern: str = field(compare=False, default="")

    def find_secrets(self, line: str):
        """Yield (start, end, secret_text) for every match on `line`.

        For a plain signature rule the whole match is the secret. For an
        entropy-checked rule (a generic `key = <value>` assignment with no
        fixed format) only group 1 — the value — is treated as the secret,
        and it's discarded unless it also looks sufficiently random.
        """
        for m in self.pattern.finditer(line):
            if self.entropy_check:
                if not m.groups():
                    continue
                secret = m.group(1)
                if not entropy_mod.is_high_entropy_secret(secret):
                    continue
                start, end = m.start(1), m.end(1)
            else:
                secret = m.group(0)
                start, end = m.start(0), m.end(0)
            yield start, end, secret


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

    entropy_check = bool(raw.get("entropy_check", False))

    try:
        pattern = re.compile(raw["pattern"])
    except re.error as exc:
        raise RuleValidationError(f"rule {raw['id']!r} has invalid regex: {exc}") from exc

    if entropy_check and pattern.groups < 1:
        raise RuleValidationError(
            f"rule {raw['id']!r} has entropy_check: true but no capture group "
            "to extract the candidate secret from"
        )

    return Rule(
        id=raw["id"],
        pattern=pattern,
        severity=severity,
        category=raw["category"],
        description=raw.get("description", ""),
        entropy_check=entropy_check,
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


DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "default_rules.yaml"


def load_default_rules() -> list:
    return load_rules(DEFAULT_RULES_PATH)
