"""Turn raw CVE/protocol matches into a prioritized risk score.

Each match gets a 0-100 exposure score from its CVSS base score, boosted
when a known exploit exists and downgraded when the match is only
"unconfirmed" (product matched, version couldn't be verified). Hosts are
then ranked by their single highest-scoring finding, which is what a
pentester triaging a target list actually needs first.
"""

from __future__ import annotations

from dataclasses import dataclass

from .cve_matcher import Match

EXPLOIT_BONUS = 10
UNCONFIRMED_PENALTY = 0.6  # multiplier applied to unconfirmed matches

SEVERITY_THRESHOLDS = (
    ("critical", 90),
    ("high", 70),
    ("medium", 40),
    ("low", 1),
)


def score_match(match: Match) -> float:
    score = match.rule.cvss * 10
    if match.rule.exploit_available:
        score += EXPLOIT_BONUS
    if match.confidence == "unconfirmed":
        score *= UNCONFIRMED_PENALTY
    return round(min(score, 100.0), 1)


def severity_for_score(score: float) -> str:
    for label, threshold in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "info"


@dataclass
class ScoredMatch:
    match: Match
    score: float
    severity: str


@dataclass
class HostRisk:
    host: str
    hostname: str
    score: float
    severity: str
    finding_count: int


def score_matches(matches: list[Match]) -> list[ScoredMatch]:
    scored = [ScoredMatch(match=m, score=score_match(m), severity="") for m in matches]
    for sm in scored:
        sm.severity = severity_for_score(sm.score)
    return sorted(scored, key=lambda sm: sm.score, reverse=True)


def rank_hosts(scored: list[ScoredMatch]) -> list[HostRisk]:
    by_host: dict[str, list[ScoredMatch]] = {}
    for sm in scored:
        by_host.setdefault(sm.match.host, []).append(sm)

    risks = []
    for host, findings in by_host.items():
        top = max(findings, key=lambda sm: sm.score)
        risks.append(
            HostRisk(
                host=host,
                hostname=findings[0].match.hostname,
                score=top.score,
                severity=top.severity,
                finding_count=len(findings),
            )
        )
    return sorted(risks, key=lambda r: r.score, reverse=True)
