"""ATT&CK coverage reporting for a rule set."""
from __future__ import annotations

from collections import defaultdict

from .rule import Rule


def coverage(rules: list[Rule], target: set[str] | None = None) -> dict:
    """Map technique -> rule ids; optionally diff against a target technique set (gaps).

    Sub-technique coverage counts toward its parent (T1059.001 covers T1059 for gap purposes).
    """
    by_tech: dict[str, list[str]] = defaultdict(list)
    untagged = []
    for r in rules:
        if not r.techniques:
            untagged.append(r.id)
        for t in r.techniques:
            by_tech[t].append(r.id)
    covered = set(by_tech) | {t.split(".")[0] for t in by_tech}
    report = {"techniques": {t: sorted(ids) for t, ids in sorted(by_tech.items())},
              "rules_without_attack_mapping": sorted(untagged), "total_rules": len(rules)}
    if target is not None:
        want = {t.upper() for t in target}
        report["target_covered"] = sorted(want & covered)
        report["target_gaps"] = sorted(want - covered)
        report["target_coverage_pct"] = round(100 * len(want & covered) / len(want), 1) if want else 100.0
    return report
