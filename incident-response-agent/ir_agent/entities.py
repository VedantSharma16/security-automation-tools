"""Lightweight extraction of the entity types the agent's tools know how to look up.

Deliberately narrower than a full IOC extractor: the agent only needs enough
structure to decide *which tools to call*, not a complete indicator taxonomy.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")

_KNOWN_TLDS = frozenset(
    "com net org io gov edu mil info biz co us uk ca de fr top online site "
    "app dev me xyz club tech cloud".split()
)


@dataclass
class Entities:
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.ips or self.domains or self.cves)


def extract_entities(text: str) -> Entities:
    """Extract deduplicated, order-preserving IPs, domains, and CVE IDs from ``text``."""
    seen_ips: dict[str, None] = {}
    for match in _IPV4_RE.finditer(text):
        value = match.group(0)
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            continue
        seen_ips.setdefault(value, None)

    seen_cves: dict[str, None] = {}
    for match in _CVE_RE.finditer(text):
        seen_cves.setdefault(match.group(0).upper(), None)

    seen_domains: dict[str, None] = {}
    for match in _DOMAIN_RE.finditer(text):
        value = match.group(0)
        if value in seen_ips:
            continue
        tld = value.rsplit(".", 1)[-1].lower()
        if tld not in _KNOWN_TLDS:
            continue
        seen_domains.setdefault(value, None)

    return Entities(ips=list(seen_ips), domains=list(seen_domains), cves=list(seen_cves))
