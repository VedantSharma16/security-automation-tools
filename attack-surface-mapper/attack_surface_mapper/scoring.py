"""Aggregate per-host findings and open ports into a single risk score."""

from __future__ import annotations

from .models import Finding, OpenPort

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
}

# Weight added per open port: a sensitive service (e.g. RDP, a database)
# being internet-facing is treated like a "high" finding; a routine web
# port is only a minor informational contributor.
_SENSITIVE_PORT_WEIGHT = 40
_ROUTINE_PORT_WEIGHT = 2

_LEVEL_THRESHOLDS: list[tuple[int, str]] = [
    (70, "critical"),
    (40, "high"),
    (15, "medium"),
    (1, "low"),
]

_LEVEL_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _level_for_score(score: int) -> str:
    for threshold, level in _LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "info"


def compute_risk(open_ports: list[OpenPort], findings: list[Finding]) -> tuple[int, str]:
    """Return (score 0-100, level) for a host given its open ports and findings.

    `level` is the more severe of the score-derived tier and the single
    highest finding severity, so e.g. one `critical` finding always yields
    a `critical` host level even if it alone wouldn't cross the score
    threshold.
    """
    score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    score += sum(
        _SENSITIVE_PORT_WEIGHT if p.sensitive else _ROUTINE_PORT_WEIGHT for p in open_ports
    )
    score = min(score, 100)

    level = _level_for_score(score)
    highest_finding_severity = max(
        (f.severity for f in findings), key=lambda s: _LEVEL_RANK.get(s, 0), default="info"
    )
    if _LEVEL_RANK.get(highest_finding_severity, 0) > _LEVEL_RANK[level]:
        level = highest_finding_severity

    return score, level
