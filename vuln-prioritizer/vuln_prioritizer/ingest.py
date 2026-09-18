"""Parse a vulnerability scan export (Nessus/Qualys/OpenVAS-style CSV) into
normalized :class:`Finding` records.

Real scanners disagree on column names, so the parser accepts a handful of
common aliases per field and normalizes everything into one schema. A row
missing a CVE is still kept (not every finding maps to a CVE), but it will
skip CVE-based enrichment (EPSS / CISA KEV) downstream.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

_HOST_KEYS = ("host", "hostname", "asset", "name")
_IP_KEYS = ("ip", "ip_address", "host_ip")
_PORT_KEYS = ("port",)
_CVE_KEYS = ("cve_id", "cve", "cve id")
_TITLE_KEYS = ("plugin_name", "title", "vulnerability", "name", "synopsis")
_SEVERITY_KEYS = ("severity", "risk")
_CVSS_KEYS = ("cvss_score", "cvss", "cvss_base_score", "cvss3_base_score")
_DESCRIPTION_KEYS = ("description", "synopsis", "summary")


@dataclass(frozen=True)
class Finding:
    host: str
    ip: str | None
    port: int | None
    cve_id: str | None
    title: str
    severity: str
    cvss_score: float | None
    description: str

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "ip": self.ip,
            "port": self.port,
            "cve_id": self.cve_id,
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
        }


class ScanFormatError(ValueError):
    """Raised when a scan export is missing required columns."""


def _normalize_row(row: dict[str, str]) -> dict[str, str]:
    return {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}


def _first(row: dict[str, str], keys: tuple[str, ...]) -> str:
    for key in keys:
        if row.get(key):
            return row[key]
    return ""


def _parse_row(row: dict[str, str]) -> Finding:
    row = _normalize_row(row)

    host = _first(row, _HOST_KEYS)
    if not host:
        raise ScanFormatError(f"row has no host/hostname column: {row}")

    port_raw = _first(row, _PORT_KEYS)
    port = None
    if port_raw:
        try:
            port = int(float(port_raw))
        except ValueError:
            port = None

    cvss_raw = _first(row, _CVSS_KEYS)
    cvss_score = None
    if cvss_raw:
        try:
            cvss_score = max(0.0, min(10.0, float(cvss_raw)))
        except ValueError:
            cvss_score = None

    cve_id = _first(row, _CVE_KEYS).upper() or None

    return Finding(
        host=host,
        ip=_first(row, _IP_KEYS) or None,
        port=port,
        cve_id=cve_id,
        title=_first(row, _TITLE_KEYS) or (cve_id or "Untitled finding"),
        severity=(_first(row, _SEVERITY_KEYS) or "unknown").lower(),
        cvss_score=cvss_score,
        description=_first(row, _DESCRIPTION_KEYS),
    )


def parse_scan_csv(path: str | Path) -> list[Finding]:
    """Parse a scan export CSV into a list of :class:`Finding`."""
    path = Path(path)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ScanFormatError(f"{path} has no header row")
        return [_parse_row(row) for row in reader]
