"""MITRE ATT&CK coverage report from rule tags."""
from __future__ import annotations

from collections import defaultdict

from .rule import Rule

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]


def coverage(rules: list[Rule]) -> dict:
    by_tactic: dict[str, set[str]] = defaultdict(set)
    untagged = []
    for r in rules:
        if not r.techniques and not r.tactics:
            untagged.append(r.id)
        for tac in r.tactics:
            by_tactic[tac].update(r.techniques)
    techniques = sorted({t for r in rules for t in r.techniques})
    missing = [t for t in TACTIC_ORDER if t not in by_tactic]
    return {
        "rules": len(rules),
        "techniques": techniques,
        "tactics": {t: sorted(by_tactic[t]) for t in TACTIC_ORDER if t in by_tactic},
        "tactic_gaps": missing,
        "untagged_rules": untagged,
    }


def render(cov: dict) -> str:
    lines = [f"ATT&CK coverage: {len(cov['techniques'])} techniques across "
             f"{len(cov['tactics'])}/{len(TACTIC_ORDER)} tactics from {cov['rules']} rules", ""]
    for tac, techs in cov["tactics"].items():
        lines.append(f"  [x] {tac:<22} {', '.join(techs) or '-'}")
    for tac in cov["tactic_gaps"]:
        lines.append(f"  [ ] {tac:<22} (no coverage)")
    if cov["untagged_rules"]:
        lines += ["", "Rules without ATT&CK tags: " + ", ".join(cov["untagged_rules"])]
    return "\n".join(lines)
