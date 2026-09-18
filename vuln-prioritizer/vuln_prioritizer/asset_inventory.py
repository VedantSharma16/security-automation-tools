"""Load an asset inventory (hostname -> business criticality + exposure).

Vulnerability scanners report technical severity only; they don't know that
`payroll-db-01` matters more than `test-vm-42`. The asset inventory supplies
that business context, which the scoring model weights alongside CVSS/EPSS.
A host missing from the inventory gets a conservative default rather than
being silently dropped or under-scored.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

VALID_CRITICALITIES = ("critical", "high", "medium", "low")


@dataclass(frozen=True)
class Asset:
    hostname: str
    criticality: str = "medium"
    internet_facing: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "criticality": self.criticality,
            "internet_facing": self.internet_facing,
            "tags": list(self.tags),
        }


DEFAULT_ASSET = Asset(hostname="(unknown)", criticality="medium", internet_facing=False)


class InventoryFormatError(ValueError):
    """Raised when the asset inventory JSON is malformed."""


def load_inventory(path: str | Path) -> dict[str, Asset]:
    """Load a JSON asset inventory into a case-insensitive hostname -> Asset map."""
    path = Path(path)
    with path.open(encoding="utf-8") as handle:
        try:
            raw = json.load(handle)
        except json.JSONDecodeError as exc:
            raise InventoryFormatError(f"{path} is not valid JSON: {exc}") from exc

    if not isinstance(raw, list):
        raise InventoryFormatError(f"{path} must contain a JSON list of asset objects")

    inventory: dict[str, Asset] = {}
    for entry in raw:
        hostname = str(entry.get("hostname", "")).strip()
        if not hostname:
            continue
        criticality = str(entry.get("criticality", "medium")).lower()
        if criticality not in VALID_CRITICALITIES:
            criticality = "medium"
        asset = Asset(
            hostname=hostname,
            criticality=criticality,
            internet_facing=bool(entry.get("internet_facing", False)),
            tags=tuple(entry.get("tags", [])),
        )
        inventory[hostname.lower()] = asset
    return inventory


def get_asset(inventory: dict[str, Asset], hostname: str) -> Asset:
    """Look up a host, case-insensitively, falling back to a medium-criticality default."""
    asset = inventory.get(hostname.lower())
    if asset is not None:
        return asset
    return Asset(hostname=hostname, criticality="medium", internet_facing=False)
