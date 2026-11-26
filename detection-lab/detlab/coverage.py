"""MITRE ATT&CK coverage and gap analysis for a rule set."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .rules import Rule

DEFAULT_REFERENCE = Path(__file__).resolve().parent.parent / "data" / "attack_techniques.json"
TACTIC_ORDER = [
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access", "discovery",
    "lateral_movement", "collection", "command_and_control", "exfiltration", "impact",
]


@dataclass
class CoverageReport:
    covered: dict[str, list[str]]           # technique -> rule titles
    by_tactic: dict[str, list[str]]         # tactic -> covered techniques
    gaps: dict[str, list[str]]              # tactic -> uncovered reference techniques
    reference: dict[str, dict]

    @property
    def reference_coverage_pct(self) -> float:
        ref = set(self.reference)
        return 100.0 * len(ref & set(self.covered)) / len(ref) if ref else 0.0

    def to_dict(self) -> dict:
        return {
            "covered_techniques": self.covered,
            "by_tactic": self.by_tactic,
            "gaps": self.gaps,
            "reference_coverage_pct": round(self.reference_coverage_pct, 1),
        }


def load_reference(path: Path | str = DEFAULT_REFERENCE) -> dict[str, dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def build_coverage(rules: list[Rule], reference: dict[str, dict] | None = None) -> CoverageReport:
    reference = load_reference() if reference is None else reference
    covered: dict[str, list[str]] = {}
    by_tactic: dict[str, set[str]] = {}
    for rule in rules:
        if rule.status == "deprecated":
            continue
        for tech in rule.techniques:
            covered.setdefault(tech, []).append(rule.title)
            # Prefer the reference's tactic mapping; fall back to the rule's own tactic tags.
            tactics = reference.get(tech, {}).get("tactics") or rule.tactics or ["unmapped"]
            for tactic in tactics:
                by_tactic.setdefault(tactic, set()).add(tech)

    gaps: dict[str, list[str]] = {}
    for tech, meta in reference.items():
        if tech in covered:
            continue
        for tactic in meta.get("tactics", []):
            gaps.setdefault(tactic, []).append(tech)

    def ordered(d: dict[str, set[str] | list[str]]) -> dict[str, list[str]]:
        keys = sorted(d, key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else len(TACTIC_ORDER))
        return {k: sorted(d[k]) for k in keys}

    return CoverageReport(
        covered={k: sorted(v) for k, v in sorted(covered.items())},
        by_tactic=ordered(by_tactic),
        gaps=ordered(gaps),
        reference=reference,
    )
