"""Detection-as-code: load and compile the JSON rule pack."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_RULES_PATH = Path(__file__).with_name("rules.json")
VALID_SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    severity: str
    owasp: str
    atlas: str
    description: str
    patterns: tuple[re.Pattern, ...]
    indirect_only: bool = False

    def search(self, text: str) -> re.Match | None:
        for pattern in self.patterns:
            match = pattern.search(text)
            if match:
                return match
        return None


@dataclass(frozen=True)
class RulePack:
    version: str
    severity_weights: dict[str, int]
    rules: tuple[Rule, ...]

    def weight(self, severity: str) -> int:
        return self.severity_weights[severity]


class RuleValidationError(ValueError):
    pass


def load_rules(path: str | Path | None = None) -> RulePack:
    """Load and validate a rule pack. Raises RuleValidationError on bad input
    so a broken custom rule fails loudly at startup instead of silently never
    matching."""
    path = Path(path) if path else DEFAULT_RULES_PATH
    data = json.loads(path.read_text(encoding="utf-8"))

    weights = data.get("severity_weights", {})
    missing = [s for s in VALID_SEVERITIES if s not in weights]
    if missing:
        raise RuleValidationError(f"severity_weights missing: {missing}")

    rules, seen = [], set()
    for raw in data.get("rules", []):
        rule_id = raw.get("id", "<no id>")
        if rule_id in seen:
            raise RuleValidationError(f"duplicate rule id {rule_id}")
        seen.add(rule_id)
        if raw.get("severity") not in VALID_SEVERITIES:
            raise RuleValidationError(f"{rule_id}: invalid severity {raw.get('severity')!r}")
        if not raw.get("patterns"):
            raise RuleValidationError(f"{rule_id}: no patterns")
        try:
            compiled = tuple(re.compile(p, re.IGNORECASE) for p in raw["patterns"])
        except re.error as exc:
            raise RuleValidationError(f"{rule_id}: bad regex: {exc}") from exc
        rules.append(
            Rule(
                id=rule_id,
                name=raw["name"],
                category=raw["category"],
                severity=raw["severity"],
                owasp=raw.get("owasp", ""),
                atlas=raw.get("atlas", ""),
                description=raw.get("description", ""),
                patterns=compiled,
                indirect_only=bool(raw.get("indirect_only", False)),
            )
        )
    return RulePack(version=str(data.get("version", "0")), severity_weights=weights, rules=tuple(rules))
