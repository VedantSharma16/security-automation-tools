"""Composite patch-priority scoring.

The model combines four independent signals into a single 0-100 priority
score, then buckets that score into a remediation tier (P1-P4). Every
component and every weight is exposed on the result (`ScoredFinding.factors`
and `.rationale`) so the score is auditable rather than a black box — a
reviewer (or an LLM writing a narrative on top of it) can see exactly why a
finding landed where it did.

    priority_score = min(100, base * criticality_weight * exposure_multiplier)
    base           = 0.40 * (cvss_score * 10)      # technical severity, 0-40
                    + 0.35 * (epss_score * 100)     # real-world exploit likelihood, 0-35
                    + 25 if in CISA KEV else 0       # confirmed active exploitation

Weights are deliberately conservative: CVSS still anchors the score (a
9.8/10 CVSS with no EPSS data is still urgent), EPSS pulls likely-to-be-
exploited mediums above unlikely-to-be-exploited criticals, and KEV
membership is close to a hard override since it means exploitation isn't
theoretical.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .asset_inventory import Asset
from .enrichment import Enrichment
from .ingest import Finding

CRITICALITY_WEIGHTS = {"critical": 1.30, "high": 1.15, "medium": 1.00, "low": 0.85}
INTERNET_FACING_MULTIPLIER = 1.15
KEV_BONUS = 25.0
CVSS_WEIGHT = 0.40
EPSS_WEIGHT = 0.35

PRIORITY_TIERS = (
    (85.0, "P1", "Emergency — remediate immediately"),
    (65.0, "P2", "High — remediate within the standard SLA"),
    (40.0, "P3", "Medium — schedule in the next patch cycle"),
    (0.0, "P4", "Low — track, no urgent action required"),
)


def tier_for_score(score: float) -> tuple[str, str]:
    for threshold, code, label in PRIORITY_TIERS:
        if score >= threshold:
            return code, label
    return PRIORITY_TIERS[-1][1], PRIORITY_TIERS[-1][2]


@dataclass(frozen=True)
class ScoredFinding:
    finding: Finding
    asset: Asset
    enrichment: Enrichment | None
    priority_score: float
    priority_tier: str
    priority_label: str
    factors: dict[str, float]
    rationale: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "finding": self.finding.to_dict(),
            "asset": self.asset.to_dict(),
            "enrichment": self.enrichment.to_dict() if self.enrichment else None,
            "priority_score": self.priority_score,
            "priority_tier": self.priority_tier,
            "priority_label": self.priority_label,
            "factors": self.factors,
            "rationale": self.rationale,
        }


def _build_rationale(
    finding: Finding, asset: Asset, enrichment: Enrichment | None, factors: dict[str, float]
) -> list[str]:
    rationale = []

    if finding.cvss_score is not None:
        rationale.append(f"CVSS base score {finding.cvss_score:.1f}/10")
    else:
        rationale.append("No CVSS score reported by the scanner")

    if enrichment and enrichment.epss_score is not None:
        pct = enrichment.epss_percentile
        pct_str = f", {pct * 100:.0f}th percentile" if pct is not None else ""
        rationale.append(f"EPSS {enrichment.epss_score:.2f} (30-day exploitation probability{pct_str})")

    if enrichment and enrichment.in_kev:
        due = f", CISA-mandated remediation due {enrichment.kev_due_date}" if enrichment.kev_due_date else ""
        rationale.append(f"Listed in the CISA Known Exploited Vulnerabilities catalog{due}")

    rationale.append(f"Asset criticality: {asset.criticality}")

    if asset.internet_facing:
        rationale.append("Asset is internet-facing")

    return rationale


def score_finding(finding: Finding, asset: Asset, enrichment: Enrichment | None) -> ScoredFinding:
    cvss_component = (finding.cvss_score or 0.0) * 10.0
    epss_component = (enrichment.epss_score or 0.0) * 100.0 if enrichment else 0.0
    kev_bonus = KEV_BONUS if (enrichment and enrichment.in_kev) else 0.0

    base = CVSS_WEIGHT * cvss_component + EPSS_WEIGHT * epss_component + kev_bonus

    criticality_weight = CRITICALITY_WEIGHTS.get(asset.criticality, 1.0)
    exposure_multiplier = INTERNET_FACING_MULTIPLIER if asset.internet_facing else 1.0

    score = min(100.0, base * criticality_weight * exposure_multiplier)
    tier_code, tier_label = tier_for_score(score)

    factors = {
        "cvss_component": round(cvss_component, 2),
        "epss_component": round(epss_component, 2),
        "kev_bonus": kev_bonus,
        "criticality_weight": criticality_weight,
        "exposure_multiplier": exposure_multiplier,
    }

    return ScoredFinding(
        finding=finding,
        asset=asset,
        enrichment=enrichment,
        priority_score=round(score, 1),
        priority_tier=tier_code,
        priority_label=tier_label,
        factors=factors,
        rationale=_build_rationale(finding, asset, enrichment, factors),
    )


def score_findings(scored: list[ScoredFinding]) -> list[ScoredFinding]:
    """Sort already-scored findings by descending priority (ties broken by CVSS)."""
    return sorted(
        scored,
        key=lambda sf: (sf.priority_score, sf.finding.cvss_score or 0.0),
        reverse=True,
    )


def build_summary(scored: list[ScoredFinding]) -> dict:
    """Aggregate stats used by both the report renderer and the narrative generator."""
    by_tier: dict[str, int] = {code: 0 for _, code, _ in PRIORITY_TIERS}
    hosts: set[str] = set()
    kev_count = 0

    for sf in scored:
        by_tier[sf.priority_tier] += 1
        hosts.add(sf.finding.host)
        if sf.enrichment and sf.enrichment.in_kev:
            kev_count += 1

    avg_score = round(sum(sf.priority_score for sf in scored) / len(scored), 1) if scored else 0.0

    return {
        "total_findings": len(scored),
        "hosts_affected": len(hosts),
        "by_tier": by_tier,
        "kev_findings": kev_count,
        "average_priority_score": avg_score,
    }
