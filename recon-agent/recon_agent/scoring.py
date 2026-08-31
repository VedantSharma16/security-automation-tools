"""Aggregate DNS/HTTP/TLS findings into a single passive-recon risk score.

Mirrors the scoring style used by the other tools in this repo
(log-triage-assistant, process_threat_hunter): small additive point rules
mapped onto a four-level severity band, kept simple and explainable rather
than a black-box model.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .http_recon import HttpFinding, RobotsFinding
from .tls_recon import TlsFinding

SEVERITY_BANDS = (
    (0, "info"),
    (3, "low"),
    (7, "medium"),
    (12, "high"),
)

SENSITIVE_PATH_HINTS = (
    "admin",
    "wp-admin",
    "phpmyadmin",
    "backup",
    "config",
    ".env",
    "staging",
    "internal",
    "test",
    "debug",
)


@dataclass
class ScoredFinding:
    points: int
    reason: str


@dataclass
class RiskAssessment:
    score: int
    severity: str
    findings: list[ScoredFinding] = field(default_factory=list)


def _band_for(score: int) -> str:
    severity = SEVERITY_BANDS[0][1]
    for threshold, name in SEVERITY_BANDS:
        if score >= threshold:
            severity = name
    return severity


def score_findings(
    http_finding: "HttpFinding | None" = None,
    robots_finding: "RobotsFinding | None" = None,
    tls_finding: "TlsFinding | None" = None,
) -> RiskAssessment:
    scored: list[ScoredFinding] = []

    if http_finding and http_finding.ok:
        for header in http_finding.missing_security_headers:
            scored.append(ScoredFinding(1, f"Missing security header: {header}"))
        if http_finding.fingerprint:
            details = ", ".join(f"{k}={v}" for k, v in http_finding.fingerprint.items())
            scored.append(ScoredFinding(2, f"Server fingerprinting headers exposed ({details})"))

    if robots_finding and robots_finding.fetched:
        hits = [
            path
            for path in robots_finding.disallowed_paths
            if any(hint in path.lower() for hint in SENSITIVE_PATH_HINTS)
        ]
        for path in hits:
            scored.append(ScoredFinding(2, f"robots.txt discloses sensitive-looking path: {path}"))

    if tls_finding:
        if not tls_finding.connected:
            scored.append(ScoredFinding(3, f"TLS connection failed: {tls_finding.error or 'unknown error'}"))
        for issue in tls_finding.issues:
            weight = 5 if "expired" in issue.lower() else 3
            scored.append(ScoredFinding(weight, issue))

    total = sum(f.points for f in scored)
    return RiskAssessment(score=total, severity=_band_for(total), findings=scored)
