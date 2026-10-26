from __future__ import annotations

from .analyzers import ANALYZERS
from .models import SEVERITY_WEIGHTS, Finding, Verdict
from .parser import ParsedEmail


def label_for(score: int) -> str:
    if score >= 70:
        return "MALICIOUS"
    if score >= 40:
        return "SUSPICIOUS"
    if score >= 15:
        return "LOW_RISK"
    return "CLEAN"


def analyze(email: ParsedEmail) -> Verdict:
    findings: list[Finding] = [f for fn in ANALYZERS for f in fn(email)]
    # Count each rule once so a message with 20 shortened links doesn't dominate.
    unique = {f.rule: f for f in reversed(findings)}
    score = min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in unique.values()))
    order = list(SEVERITY_WEIGHTS)
    findings.sort(key=lambda f: -order.index(f.severity))
    return Verdict(score, label_for(score), findings)
