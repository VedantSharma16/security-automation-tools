"""MITRE ATT&CK coverage reporting for a rule set."""
from __future__ import annotations

from collections import defaultdict

from .rule import Rule


def coverage(rules: list[Rule]) -> dict:
    by_tech: dict[str, list[str]] = defaultdict(list)
    by_tactic: dict[str, int] = defaultdict(int)
    untagged = []
    for r in rules:
        if not r.attack_techniques:
            untagged.append(r.title)
        for t in r.attack_techniques:
            by_tech[t].append(r.title)
        for tac in r.attack_tactics:
            by_tactic[tac] += 1
    return {
        "rules": len(rules),
        "techniques": {t: sorted(v) for t, v in sorted(by_tech.items())},
        "tactics": dict(sorted(by_tactic.items())),
        "untagged_rules": untagged,
    }


def gaps(rules: list[Rule], wanted: list[str]) -> list[str]:
    """Techniques in `wanted` with no rule (a sub-technique covers its parent)."""
    have = {t for r in rules for t in r.attack_techniques}
    have |= {t.split(".")[0] for t in have}
    return sorted(w.upper() for w in wanted if w.upper() not in have)
