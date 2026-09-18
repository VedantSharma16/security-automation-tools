"""Wires ingest -> asset lookup -> enrichment -> scoring into one call."""

from __future__ import annotations

from pathlib import Path

from .asset_inventory import get_asset, load_inventory
from .enrichment import DEFAULT_EPSS_PATH, DEFAULT_KEV_PATH, enrich_finding, load_epss_scores, load_kev_catalog
from .ingest import parse_scan_csv
from .scoring import ScoredFinding, score_finding, score_findings


def prioritize(
    scan_path: str | Path,
    assets_path: str | Path | None = None,
    kev_path: str | Path = DEFAULT_KEV_PATH,
    epss_path: str | Path = DEFAULT_EPSS_PATH,
) -> list[ScoredFinding]:
    """Run the full pipeline and return findings sorted by descending priority."""
    findings = parse_scan_csv(scan_path)
    inventory = load_inventory(assets_path) if assets_path else {}
    kev_catalog = load_kev_catalog(kev_path)
    epss_scores = load_epss_scores(epss_path)

    scored = []
    for finding in findings:
        asset = get_asset(inventory, finding.host)
        enrichment = enrich_finding(finding, kev_catalog, epss_scores)
        scored.append(score_finding(finding, asset, enrichment))

    return score_findings(scored)
