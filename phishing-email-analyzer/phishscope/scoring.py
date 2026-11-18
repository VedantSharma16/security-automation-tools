"""Combine findings into a 0-100 risk score and a triage verdict."""

from __future__ import annotations

from .detectors import SEVERITY_WEIGHTS, Finding

MALICIOUS_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 25


def risk_score(findings: list[Finding]) -> int:
    # Count each rule once at full weight, repeats at half weight, so ten
    # shortener links don't outweigh one confirmed executable attachment.
    seen: set[str] = set()
    total = 0.0
    for f in findings:
        weight = SEVERITY_WEIGHTS[f.severity]
        total += weight if f.rule not in seen else weight / 2
        seen.add(f.rule)
    return min(100, round(total))


def verdict(findings: list[Finding]) -> str:
    score = risk_score(findings)
    if score >= MALICIOUS_THRESHOLD or any(f.severity == "CRITICAL" for f in findings):
        return "MALICIOUS"
    if score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "LIKELY_BENIGN"


def severity_breakdown(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_WEIGHTS}
    for f in findings:
        counts[f.severity] += 1
    return counts
