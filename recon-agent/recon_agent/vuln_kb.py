"""A small, offline knowledge base of well-known service/version CVEs.

This mirrors public advisory data (CVE ID, affected version(s), severity,
and a one-line description) for a curated set of historically significant,
widely-taught vulnerabilities. It's intentionally informational only — no
exploit code — so the agent can flag "this fingerprint looks like it might
be affected by CVE-X, go verify" the same way a human analyst recognizes a
banner and goes to check an advisory.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "known_service_vulnerabilities.json"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class VulnMatch:
    service: str
    version: str | None
    port: int | None
    cve: str
    severity: str
    description: str
    reference: str

    def to_dict(self) -> dict:
        return asdict(self)


class VulnKnowledgeBase:
    def __init__(self, db_path: Path | None = None):
        path = db_path or DEFAULT_DB_PATH
        with open(path, "r", encoding="utf-8") as f:
            self._entries = json.load(f)

    def lookup(self, service: str | None, version: str | None, port: int | None = None) -> list[VulnMatch]:
        if not service or not version:
            return []
        service_norm = service.strip().lower()
        matches = []
        for entry in self._entries:
            if entry["service"].lower() != service_norm:
                continue
            if self._version_matches(entry, version):
                matches.append(
                    VulnMatch(
                        service=service,
                        version=version,
                        port=port,
                        cve=entry["cve"],
                        severity=entry["severity"],
                        description=entry["description"],
                        reference=entry.get("reference", ""),
                    )
                )
        return matches

    @staticmethod
    def _version_matches(entry: dict, version: str) -> bool:
        versions = entry.get("versions")
        if versions and version in versions:
            return True
        pattern = entry.get("version_regex")
        if pattern and re.match(pattern, version):
            return True
        return False
