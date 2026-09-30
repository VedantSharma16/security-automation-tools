from __future__ import annotations

from .analyzers import ALL_CHECKS
from .models import SEVERITY_WEIGHTS, Finding, ParsedEmail, Verdict


def label_for(score: int) -> str:
    if score >= 70:
        return "MALICIOUS"
    if score >= 35:
        return "SUSPICIOUS"
    if score >= 15:
        return "LOW-RISK"
    return "CLEAN"


def assess(p: ParsedEmail) -> Verdict:
    findings: list[Finding] = [f for check in ALL_CHECKS for f in check(p)]
    # Diminishing returns: repeated hits of the same rule only count 25% after the first.
    seen: dict[str, int] = {}
    score = 0.0
    for f in sorted(findings, key=lambda x: -SEVERITY_WEIGHTS[x.severity]):
        w = SEVERITY_WEIGHTS[f.severity]
        score += w if f.rule not in seen else w * 0.25
        seen[f.rule] = seen.get(f.rule, 0) + 1
    score_i = min(100, round(score))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: order[x.severity])
    return Verdict(score_i, label_for(score_i), findings)
