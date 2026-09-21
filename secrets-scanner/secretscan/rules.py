"""Loading and representing secret-detection rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .entropy import is_high_entropy

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "default_rules.yaml"


class RuleValidationError(ValueError):
    """Raised when a rule definition is malformed."""


@dataclass(frozen=True)
class Match:
    start: int
    end: int
    text: str
    secret_text: str


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern
    severity: str
    category: str
    description: str
    entropy_group: int | None = None
    min_entropy: float = 4.0
    min_length: int = 16
    raw_pattern: str = field(compare=False, default="")

    def find_all(self, text: str) -> list:
        """Return every non-overlapping match of this rule in ``text``.

        When ``entropy_group`` is set, a regex hit is only kept if the
        captured group also looks random enough per :func:`is_high_entropy`
        — this is how the generic "assignment to a secret-looking value"
        rules avoid flagging every placeholder string in a codebase. In that
        case ``Match.secret_text`` is that captured value alone (not the
        surrounding ``key = "..."`` syntax), so redaction and fingerprints
        are based on just the secret, not the whole assignment.
        """
        matches = []
        for m in self.pattern.finditer(text):
            secret_text = m.group(0)
            if self.entropy_group is not None:
                try:
                    candidate = m.group(self.entropy_group)
                except IndexError:
                    candidate = None
                if candidate is None:
                    continue
                if not is_high_entropy(
                    candidate, threshold=self.min_entropy, min_length=self.min_length
                ):
                    continue
                secret_text = candidate
            matches.append(
                Match(start=m.start(), end=m.end(), text=m.group(0), secret_text=secret_text)
            )
        return matches


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

    entropy_group = raw.get("entropy_group")
    if entropy_group is not None and not isinstance(entropy_group, int):
        raise RuleValidationError(f"rule {raw['id']!r} entropy_group must be an integer")

    return Rule(
        id=raw["id"],
        pattern=pattern,
        severity=severity,
        category=raw["category"],
        description=raw.get("description", ""),
        entropy_group=entropy_group,
        min_entropy=float(raw.get("min_entropy", 4.0)),
        min_length=int(raw.get("min_length", 16)),
        raw_pattern=raw["pattern"],
    )


def load_rules(path=None) -> list:
    """Load and validate a YAML rule file, returning a list of Rule objects."""
    path = path or DEFAULT_RULES_PATH
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
