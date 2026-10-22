"""MITRE ATT&CK coverage summary for a rule set."""

from __future__ import annotations

from collections import defaultdict

from .rule import Rule


def coverage(rules: list[Rule]) -> dict:
    by_tech: dict[str, list[str]] = defaultdict(list)
    by_tactic: dict[str, int] = defaultdict(int)
    untagged = []
    for r in rules:
        if not r.techniques:
            untagged.append(r.title)
        for t in r.techniques:
            by_tech[t].append(r.title)
        for tac in r.tactics:
            by_tactic[tac] += 1
    return {"rules": len(rules), "techniques": dict(sorted(by_tech.items())),
            "tactics": dict(sorted(by_tactic.items())), "untagged_rules": untagged}
