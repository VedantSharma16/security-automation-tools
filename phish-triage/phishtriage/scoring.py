"""Risk scoring."""
from __future__ import annotations

from .models import SEVERITY_WEIGHTS, Finding


def score(findings: list[Finding]) -> tuple[int, str]:
    """Sum severity weights (capped at 100) and map to a verdict."""
    total = min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in findings))
    if any(f.severity == "critical" for f in findings) or total >= 70:
        verdict = "malicious"
    elif total >= 35:
        verdict = "suspicious"
    elif total >= 10:
        verdict = "low-risk"
    else:
        verdict = "clean"
    return total, verdict
