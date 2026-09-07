"""Severity -> numeric risk score, shared by report building and filtering."""

from __future__ import annotations

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
SEVERITY_WEIGHTS = {"info": 1, "low": 3, "medium": 10, "high": 20, "critical": 40}


def highest_severity(findings: list[dict]) -> str:
    if not findings:
        return "none"
    return max((f["severity"] for f in findings), key=SEVERITY_ORDER.index)


def risk_score(findings: list[dict]) -> int:
    total = sum(SEVERITY_WEIGHTS[f["severity"]] for f in findings)
    return min(total, 100)


def meets_min_severity(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(minimum)
