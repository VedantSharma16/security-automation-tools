"""Match parsed nmap services against a local vulnerability-rule database.

The database (see data/cve_db.json) holds two kinds of rules:

- "cve": a known CVE tied to a product and an inclusive version range.
  Matched only against services that expose both a product/service name
  nmap can identify and a parseable version string.
- "insecure_protocol": a structural weakness (e.g. Telnet is cleartext)
  that applies to the protocol regardless of version.

Version comparison is intentionally loose: real-world version strings
(e.g. "7.2p2", "2.4.49") are reduced to their leading dotted-numeric
prefix and compared as tuples. A version nmap couldn't identify, or one
that doesn't parse, is never silently dropped -- it's surfaced as an
"unconfirmed" match so an analyst can still check it by hand.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .nmap_parser import Host, Port

_VERSION_RE = re.compile(r"\d+(?:\.\d+)*")


@dataclass
class VulnRule:
    rule_id: str
    rule_type: str  # "cve" | "insecure_protocol"
    product_aliases: list[str]
    title: str
    description: str
    cvss: float
    severity: str
    exploit_available: bool
    reference: str
    version_min: str | None = None
    version_max: str | None = None


@dataclass
class Match:
    host: str
    hostname: str
    port_id: int
    protocol: str
    service_label: str
    rule: VulnRule
    confidence: str  # "confirmed" | "unconfirmed"


def load_rules(path: str | Path) -> list[VulnRule]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [VulnRule(**entry) for entry in raw]


def _parse_version(version: str) -> tuple[int, ...] | None:
    match = _VERSION_RE.search(version)
    if not match:
        return None
    return tuple(int(part) for part in match.group(0).split("."))


def _in_range(version: tuple[int, ...], low: tuple[int, ...], high: tuple[int, ...]) -> bool:
    width = max(len(version), len(low), len(high))
    v = version + (0,) * (width - len(version))
    lo = low + (0,) * (width - len(low))
    hi = high + (0,) * (width - len(high))
    return lo <= v <= hi


def _product_matches(port: Port, aliases: list[str]) -> bool:
    haystack = f"{port.service} {port.product}".lower()
    return any(alias.lower() in haystack for alias in aliases)


def _match_port(port: Port, rule: VulnRule) -> str | None:
    """Return a confidence level ('confirmed'/'unconfirmed') or None if the rule doesn't apply."""
    if not _product_matches(port, rule.product_aliases):
        return None

    if rule.rule_type == "insecure_protocol":
        return "confirmed"

    # "cve" rules need a version to confirm against.
    if not rule.version_min or not rule.version_max:
        return "unconfirmed"

    port_version = _parse_version(port.version)
    if port_version is None:
        return "unconfirmed"

    low = _parse_version(rule.version_min)
    high = _parse_version(rule.version_max)
    if low is None or high is None:
        return "unconfirmed"

    return "confirmed" if _in_range(port_version, low, high) else None


def match_hosts(hosts: list[Host], rules: list[VulnRule]) -> list[Match]:
    """Correlate every open port across all hosts against the rule database."""
    matches: list[Match] = []
    for host in hosts:
        for port in host.open_ports():
            for rule in rules:
                confidence = _match_port(port, rule)
                if confidence is None:
                    continue
                matches.append(
                    Match(
                        host=host.address,
                        hostname=host.hostname,
                        port_id=port.port_id,
                        protocol=port.protocol,
                        service_label=port.display_name() or port.service,
                        rule=rule,
                        confidence=confidence,
                    )
                )
    return matches
