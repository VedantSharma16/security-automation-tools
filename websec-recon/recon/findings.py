"""Shared finding model and risk scoring used by every recon module.

Every check in this project (DNS, ports, HTTP headers, TLS) returns a list
of ``Finding`` objects instead of printing directly, so results from all
four modules can be merged into one report and scored consistently.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ["info", "low", "medium", "high", "critical"]

# Points contributed to the overall 0-100 risk score by a single finding of
# each severity. Capped in `score_findings` so a handful of low-severity
# findings can't outweigh one critical.
_SEVERITY_WEIGHT = {
    "info": 0,
    "low": 3,
    "medium": 10,
    "high": 25,
    "critical": 45,
}


@dataclass
class Finding:
    category: str  # "dns" | "ports" | "http_headers" | "tls"
    title: str
    severity: str
    description: str
    recommendation: str = ""
    evidence: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"invalid severity {self.severity!r}, must be one of {SEVERITIES}"
            )

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


def score_findings(findings: list[Finding]) -> dict:
    """Aggregate findings into an overall 0-100 risk score and a label.

    The score is a capped sum of per-severity weights rather than a plain
    average, so one critical finding always dominates a pile of info-level
    ones instead of being diluted by them.
    """
    counts = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1

    raw = sum(_SEVERITY_WEIGHT[sev] * counts[sev] for sev in SEVERITIES)
    score = min(100, raw)

    if counts["critical"]:
        label = "critical"
    elif score >= 60:
        label = "high"
    elif score >= 30:
        label = "medium"
    elif score > 0:
        label = "low"
    else:
        label = "clean"

    return {"score": score, "label": label, "counts": counts}
