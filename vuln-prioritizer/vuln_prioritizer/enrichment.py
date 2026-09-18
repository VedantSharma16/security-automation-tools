"""Enrich CVE findings with real-world exploitation signal.

Two local, bundled data sources (small hand-curated samples, not live feeds
— see data/README notes in each file):

- CISA's Known Exploited Vulnerabilities (KEV) catalog: CVEs with
  *confirmed* in-the-wild exploitation. Presence on this list is one of the
  strongest "patch this now" signals available.
- EPSS (Exploit Prediction Scoring System): a probability (0-1) that a CVE
  will be exploited in the wild in the next 30 days, published by FIRST.org.

CVSS alone answers "how bad is this if exploited"; EPSS + KEV answer "how
likely is this to actually be exploited" — prioritizing on CVSS alone is a
well-documented vuln-management anti-pattern this module exists to correct.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .ingest import Finding

DEFAULT_KEV_PATH = Path(__file__).resolve().parent.parent / "data" / "kev_catalog_sample.json"
DEFAULT_EPSS_PATH = Path(__file__).resolve().parent.parent / "data" / "epss_scores_sample.json"


@dataclass(frozen=True)
class Enrichment:
    cve_id: str
    in_kev: bool
    kev_due_date: str | None
    kev_vulnerability_name: str | None
    epss_score: float | None
    epss_percentile: float | None

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "in_kev": self.in_kev,
            "kev_due_date": self.kev_due_date,
            "kev_vulnerability_name": self.kev_vulnerability_name,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
        }


def load_kev_catalog(path: str | Path = DEFAULT_KEV_PATH) -> dict[str, dict]:
    """Load the KEV catalog into a {CVE_ID: entry} map."""
    with Path(path).open(encoding="utf-8") as handle:
        raw = json.load(handle)
    return {entry["cveID"].upper(): entry for entry in raw.get("vulnerabilities", [])}


def load_epss_scores(path: str | Path = DEFAULT_EPSS_PATH) -> dict[str, dict]:
    """Load EPSS scores into a {CVE_ID: {"epss": float, "percentile": float}} map."""
    with Path(path).open(encoding="utf-8") as handle:
        raw = json.load(handle)
    return {cve.upper(): scores for cve, scores in raw.get("scores", {}).items()}


def enrich_finding(
    finding: Finding,
    kev_catalog: dict[str, dict],
    epss_scores: dict[str, dict],
) -> Enrichment | None:
    """Return enrichment for a finding's CVE, or None if it has no CVE."""
    if not finding.cve_id:
        return None

    cve_id = finding.cve_id.upper()
    kev_entry = kev_catalog.get(cve_id)
    epss_entry = epss_scores.get(cve_id)

    return Enrichment(
        cve_id=cve_id,
        in_kev=kev_entry is not None,
        kev_due_date=kev_entry.get("dueDate") if kev_entry else None,
        kev_vulnerability_name=kev_entry.get("vulnerabilityName") if kev_entry else None,
        epss_score=float(epss_entry["epss"]) if epss_entry else None,
        epss_percentile=float(epss_entry["percentile"]) if epss_entry else None,
    )
