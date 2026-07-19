"""Local, offline enrichment of extracted indicators.

Looks indicators up against a small bundled "threat intel" JSON file and
flags network-hygiene facts (private/reserved IP ranges) that change how
an analyst should read a hit. This module intentionally has no network
dependency: swap :func:`load_threat_intel` for a call to a real feed
(MISP, OTX, VirusTotal, an internal blocklist API, ...) to go live.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path

from ioc_triage.extractor import Indicator

DEFAULT_THREAT_INTEL_PATH = Path(__file__).resolve().parent.parent / "data" / "known_malicious_indicators.json"


@dataclass
class EnrichmentResult:
    value: str
    category: str
    is_known_malicious: bool
    confidence: str | None
    source: str | None
    notes: str

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "category": self.category,
            "is_known_malicious": self.is_known_malicious,
            "confidence": self.confidence,
            "source": self.source,
            "notes": self.notes,
        }


def load_threat_intel(path: Path | str = DEFAULT_THREAT_INTEL_PATH) -> dict[tuple[str, str], dict]:
    """Load the bundled demo threat-intel feed into a ``(category, value)`` map."""
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    return {
        (entry["category"], entry["value"].lower()): entry
        for entry in raw.get("indicators", [])
    }


def _private_ip_notes(value: str) -> str | None:
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        return None
    if addr.is_private:
        return "RFC 1918 private address — internal asset, not internet-routable."
    if addr.is_loopback:
        return "Loopback address."
    if addr.is_link_local:
        return "Link-local address."
    return None


def enrich_indicator(indicator: Indicator, threat_intel: dict[tuple[str, str], dict]) -> EnrichmentResult:
    """Enrich a single indicator against the loaded threat-intel map."""
    key = (indicator.category, indicator.value.lower())
    hit = threat_intel.get(key)

    if hit:
        return EnrichmentResult(
            value=indicator.value,
            category=indicator.category,
            is_known_malicious=True,
            confidence=hit.get("confidence"),
            source=hit.get("source"),
            notes=hit.get("notes", ""),
        )

    if indicator.category == "ipv4":
        private_note = _private_ip_notes(indicator.value)
        if private_note:
            return EnrichmentResult(
                value=indicator.value,
                category=indicator.category,
                is_known_malicious=False,
                confidence=None,
                source=None,
                notes=private_note,
            )

    return EnrichmentResult(
        value=indicator.value,
        category=indicator.category,
        is_known_malicious=False,
        confidence=None,
        source=None,
        notes="No match in local threat-intel feed.",
    )


def enrich_indicators(
    indicators: list[Indicator], threat_intel: dict[tuple[str, str], dict] | None = None
) -> list[EnrichmentResult]:
    """Enrich a batch of indicators, loading the default feed if none is supplied."""
    if threat_intel is None:
        threat_intel = load_threat_intel()
    return [enrich_indicator(indicator, threat_intel) for indicator in indicators]
