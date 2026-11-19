"""Combine findings into a 0-100 risk score and a triage verdict.

Rules:
* Repeated findings from the same check (e.g. five bad links) don't stack
  linearly: the strongest counts in full, each additional one adds 25%.
* Content-only signals (urgency, credential wording, payment wording) are
  halved when the sender is an authenticated protected domain, because real
  security notifications from e.g. Microsoft legitimately use that language.
* Any critical finding floors the score at the "likely_phishing" band: a
  single disguised executable is enough to quarantine, whatever else is clean.
"""

from __future__ import annotations

from .checks import SEVERITY_ORDER, Finding

CONTENT_ONLY_CHECKS = {"urgency_pressure", "credential_lure", "bec_payment_lure"}

VERDICT_BANDS = [  # (minimum score, verdict)
    (70, "malicious"),
    (45, "likely_phishing"),
    (20, "suspicious"),
    (0, "clean"),
]
CRITICAL_FLOOR = 45


def verdict_for(score: int) -> str:
    for minimum, verdict in VERDICT_BANDS:
        if score >= minimum:
            return verdict
    return "clean"


def score_findings(findings: list[Finding], trusted_sender: bool = False) -> dict:
    by_check: dict[str, list[int]] = {}
    for f in findings:
        points = f.score
        if trusted_sender and f.check in CONTENT_ONLY_CHECKS:
            points //= 2
        by_check.setdefault(f.check, []).append(points)

    total = 0.0
    for points in by_check.values():
        points.sort(reverse=True)
        total += points[0] + 0.25 * sum(points[1:])
    score = min(100, round(total))

    if any(f.severity == "critical" for f in findings):
        score = max(score, CRITICAL_FLOOR)

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    highest = max((f.severity for f in findings), key=SEVERITY_ORDER.index, default="none")

    return {
        "risk_score": score,
        "verdict": verdict_for(score),
        "highest_severity": highest,
        "severity_counts": counts,
        "total_findings": len(findings),
        "trusted_sender_dampening": trusted_sender,
    }
