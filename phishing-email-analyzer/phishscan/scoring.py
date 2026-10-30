from __future__ import annotations

from .models import Finding, Verdict

SUSPICIOUS_AT = 25
PHISHING_AT = 60


def score(findings: list[Finding]) -> Verdict:
    """Sum points, capping each (check, description) so repeated hits don't dominate."""
    seen: dict[tuple[str, str], int] = {}
    for f in findings:
        key = (f.check, f.description)
        seen[key] = min(seen.get(key, 0) + f.points, f.points * 2)
    total = min(100, sum(seen.values()))
    label = "likely_phishing" if total >= PHISHING_AT else "suspicious" if total >= SUSPICIOUS_AT else "clean"
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return Verdict(total, label, sorted(findings, key=lambda f: order[f.severity]))
