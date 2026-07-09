"""Loads detection rules and matches them against log events.

Rules are externalized to YAML so the detection logic can grow without
touching code -- each rule maps a regex pattern to a MITRE ATT&CK
technique and a severity, which is what lets the rest of the pipeline
produce a triaged, prioritized report instead of a flat list of hits.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .models import Finding, LogEvent, Rule, Severity

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent.parent / "rules" / "default_rules.yaml"


class RuleLoadError(ValueError):
    """Raised when a rules file is malformed."""


def load_rules(path: str | Path | None = None) -> list[Rule]:
    path = Path(path) if path else DEFAULT_RULES_PATH
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise RuleLoadError(f"{path}: expected a top-level 'rules' list")

    rules = []
    seen_ids = set()
    for entry in raw_rules:
        try:
            rule_id = entry["id"]
            pattern = entry["pattern"]
            severity = Severity.from_str(entry["severity"])
        except (KeyError, TypeError) as exc:
            raise RuleLoadError(f"{path}: rule missing required field {exc}") from exc
        except Exception as exc:
            raise RuleLoadError(f"{path}: rule '{entry.get('id', '?')}' has invalid severity") from exc

        if rule_id in seen_ids:
            raise RuleLoadError(f"{path}: duplicate rule id '{rule_id}'")
        seen_ids.add(rule_id)

        try:
            re.compile(pattern)
        except re.error as exc:
            raise RuleLoadError(f"{path}: rule '{rule_id}' has invalid regex: {exc}") from exc

        rules.append(
            Rule(
                id=rule_id,
                name=entry.get("name", rule_id),
                pattern=pattern,
                severity=severity,
                mitre_technique=entry.get("mitre_technique", "N/A"),
                description=entry.get("description", ""),
            )
        )
    return rules


class RuleEngine:
    """Compiles rules once and scans events in a single pass."""

    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self._compiled = [(rule, re.compile(rule.pattern, re.IGNORECASE)) for rule in rules]

    @classmethod
    def from_file(cls, path: str | Path | None = None) -> "RuleEngine":
        return cls(load_rules(path))

    def scan(self, events: list[LogEvent]) -> list[Finding]:
        findings = []
        for event in events:
            for rule, compiled in self._compiled:
                if compiled.search(event.raw):
                    findings.append(Finding(rule=rule, event=event))
        return findings
