"""Check extracted IOCs against a local threat-intel feed.

The feed is a small curated JSON file (``data/known_malicious_indicators.json``)
rather than a live threat-intel API, so enrichment is deterministic, free, and
works fully offline — appropriate for a portfolio demo and for CI.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "known_malicious_indicators.json"


@lru_cache(maxsize=1)
def _load_feed(path: str = str(_DATA_PATH)) -> dict:
    with open(path, encoding="utf-8") as handle:
        records = json.load(handle)
    index: dict[str, dict] = {}
    for record in records:
        index[record["value"].lower()] = record
    return index


def enrich_indicators(indicators: dict) -> list[dict]:
    """Cross-reference every extracted indicator against the local feed.

    Returns one entry per checked indicator (not just hits), each with
    ``is_known_malicious`` so callers can distinguish "checked, clean" from
    "not checked".
    """
    feed = _load_feed()
    results: list[dict] = []

    def _check(value: str, category: str) -> dict:
        hit = feed.get(value.lower())
        if hit:
            return {
                "value": value,
                "category": category,
                "is_known_malicious": True,
                "confidence": hit["confidence"],
                "source": hit["source"],
                "notes": hit["notes"],
            }
        return {
            "value": value,
            "category": category,
            "is_known_malicious": False,
            "confidence": None,
            "source": None,
            "notes": None,
        }

    for ip in indicators.get("ips", []):
        results.append(_check(ip["value"], "ip"))
    for domain in indicators.get("domains", []):
        results.append(_check(domain, "domain"))
    for url in indicators.get("urls", []):
        results.append(_check(url, "url"))
    for hash_entry in indicators.get("hashes", []):
        results.append(_check(hash_entry["value"], "hash"))

    return results


def known_malicious_hits(enrichment: list[dict]) -> list[dict]:
    return [entry for entry in enrichment if entry["is_known_malicious"]]
