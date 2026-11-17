"""MITRE ATT&CK tactic metadata and rule-set coverage reporting."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

# Enterprise tactics in kill-chain order (Sigma tag form -> display name).
TACTICS: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}
TACTIC_ORDER = {t: i for i, t in enumerate(TACTICS)}


@dataclass
class Coverage:
    by_tactic: dict[str, list[str]] = field(default_factory=dict)  # tactic -> rule titles
    techniques: dict[str, list[str]] = field(default_factory=dict)  # technique -> rule titles
    untagged: list[str] = field(default_factory=list)

    @property
    def gaps(self) -> list[str]:
        return [t for t in TACTICS if not self.by_tactic.get(t)]

    @property
    def percent(self) -> float:
        return 100.0 * (len(TACTICS) - len(self.gaps)) / len(TACTICS)

    def to_markdown(self) -> str:
        lines = [
            "# ATT&CK Coverage",
            "",
            f"Tactic coverage: **{len(TACTICS) - len(self.gaps)}/{len(TACTICS)}** "
            f"({self.percent:.0f}%) · Techniques covered: **{len(self.techniques)}**",
            "",
            "| Tactic | Rules | Covered by |",
            "|---|---:|---|",
        ]
        for key, name in TACTICS.items():
            rules = self.by_tactic.get(key, [])
            mark = "" if rules else " ⚠️"
            lines.append(f"| {name}{mark} | {len(rules)} | {', '.join(rules) or '—'} |")
        if self.techniques:
            lines += ["", "## Techniques", "", "| Technique | Rules |", "|---|---|"]
            for tech in sorted(self.techniques):
                url = f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"
                lines.append(f"| [{tech}]({url}) | {', '.join(self.techniques[tech])} |")
        if self.untagged:
            lines += ["", f"**Untagged rules:** {', '.join(self.untagged)}"]
        return "\n".join(lines) + "\n"


def coverage(rules: Iterable["Rule"]) -> Coverage:  # noqa: F821 - forward ref
    by_tactic: dict[str, list[str]] = defaultdict(list)
    techniques: dict[str, list[str]] = defaultdict(list)
    untagged: list[str] = []
    for rule in rules:
        if not rule.tactics and not rule.techniques:
            untagged.append(rule.title)
        for t in rule.tactics:
            by_tactic[t].append(rule.title)
        for t in rule.techniques:
            techniques[t].append(rule.title)
    return Coverage(dict(by_tactic), dict(techniques), untagged)
