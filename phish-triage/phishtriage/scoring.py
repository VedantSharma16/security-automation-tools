"""Turn findings into a 0-100 risk score and a verdict.

Scoring rules, chosen to be explainable to an analyst:

* Each distinct rule contributes the weight of its highest-severity hit once;
  repeated hits of the same rule add only a small bonus, so one email with
  twenty identical bad links doesn't outscore an email with several
  independent red flags.
* Independent evidence is worth more than repeated evidence: when two or more
  categories (header / url / attachment / content) each have a medium+
  finding, a corroboration bonus is added.
"""

from __future__ import annotations

from dataclasses import dataclass

from .checks import SEVERITY_ORDER, Finding

WEIGHTS = {"info": 0, "low": 5, "medium": 15, "high": 30, "critical": 50}
REPEAT_BONUS = 3
REPEAT_BONUS_CAP = 9
CORROBORATION_BONUS = 10

MALICIOUS_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 25


@dataclass
class Score:
    risk_score: int
    verdict: str  # clean | suspicious | malicious
    highest_severity: str
    categories: list[str]
    severity_counts: dict[str, int]

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def score(findings: list[Finding]) -> Score:
    per_rule: dict[str, list[Finding]] = {}
    for f in findings:
        per_rule.setdefault(f.rule_id, []).append(f)

    total = 0
    for hits in per_rule.values():
        top = max(WEIGHTS[h.severity] for h in hits)
        total += top + min(REPEAT_BONUS * (len(hits) - 1), REPEAT_BONUS_CAP)

    strong_categories = {f.category for f in findings if WEIGHTS[f.severity] >= WEIGHTS["medium"]}
    if len(strong_categories) >= 2:
        total += CORROBORATION_BONUS

    risk = min(100, total)
    if risk >= MALICIOUS_THRESHOLD:
        verdict = "malicious"
    elif risk >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "clean"

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    highest = max((f.severity for f in findings), key=SEVERITY_ORDER.index, default="info")

    return Score(
        risk_score=risk,
        verdict=verdict,
        highest_severity=highest,
        categories=sorted({f.category for f in findings}),
        severity_counts=counts,
    )
