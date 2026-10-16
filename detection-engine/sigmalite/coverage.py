"""MITRE ATT&CK coverage summary derived from rule tags."""

from __future__ import annotations

from collections import defaultdict

from .rules import Rule

TACTIC_ORDER = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
]


def coverage(rules: list[Rule]) -> dict:
    by_tactic: dict[str, set[str]] = defaultdict(set)
    for r in rules:
        for tac in r.tactics or ["untagged"]:
            by_tactic[tac].update(r.techniques)
    techniques = sorted({t for r in rules for t in r.techniques})
    ordered = [t for t in TACTIC_ORDER if t in by_tactic]
    ordered += sorted(set(by_tactic) - set(ordered))
    return {
        "rules": len(rules),
        "techniques": techniques,
        "missing_tactics": [t for t in TACTIC_ORDER if t not in by_tactic],
        "by_tactic": {t: sorted(by_tactic[t]) for t in ordered},
    }
