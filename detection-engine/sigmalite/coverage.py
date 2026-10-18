"""MITRE ATT&CK coverage summary derived from rule tags."""
from __future__ import annotations

from collections import defaultdict

from .rules import Rule


def coverage(rules: list[Rule]) -> dict:
    by_tech: dict[str, list[str]] = defaultdict(list)
    by_tactic: dict[str, list[str]] = defaultdict(list)
    untagged = []
    for r in rules:
        if not r.techniques:
            untagged.append(r.id)
        for t in r.techniques:
            by_tech[t].append(r.id)
        for t in r.tactics:
            by_tactic[t].append(r.id)
    return {
        "rules": len(rules),
        "techniques": {k: sorted(v) for k, v in sorted(by_tech.items())},
        "tactics": {k: sorted(v) for k, v in sorted(by_tactic.items())},
        "untagged_rules": sorted(untagged),
    }


def render(cov: dict) -> str:
    lines = [f"{cov['rules']} rules cover {len(cov['techniques'])} techniques "
             f"across {len(cov['tactics'])} tactics", "", "Tactics:"]
    lines += [f"  {t:<22} {len(ids)} rule(s)" for t, ids in cov["tactics"].items()]
    lines += ["", "Techniques:"]
    lines += [f"  {t:<10} {', '.join(ids)}" for t, ids in cov["techniques"].items()]
    if cov["untagged_rules"]:
        lines += ["", "Rules with no ATT&CK technique tag: " + ", ".join(cov["untagged_rules"])]
    return "\n".join(lines)
