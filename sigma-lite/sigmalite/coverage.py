"""MITRE ATT&CK coverage reporting for a rule set."""
from __future__ import annotations

from collections import defaultdict

from .rule import Rule

TACTIC_ORDER = [
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access", "discovery",
    "lateral_movement", "collection", "command_and_control", "exfiltration", "impact",
]


def coverage(rules: list[Rule]) -> dict:
    tactics: dict[str, set[str]] = defaultdict(set)
    techniques: dict[str, list[str]] = defaultdict(list)
    untagged = []
    for r in rules:
        if not r.techniques:
            untagged.append(r.id)
        for t in r.techniques:
            techniques[t].append(r.id)
            for tac in r.tactics:
                tactics[tac].add(t)
    gaps = [t for t in TACTIC_ORDER if t not in tactics]
    return {
        "rules": len(rules),
        "techniques": {k: sorted(v) for k, v in sorted(techniques.items())},
        "tactics": {t: sorted(tactics[t]) for t in TACTIC_ORDER if t in tactics},
        "tactic_gaps": gaps,
        "untagged_rules": untagged,
    }
