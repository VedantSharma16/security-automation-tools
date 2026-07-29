"""Loading and compiling YAML-defined secret-detection signatures."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Signature:
    id: str
    pattern: re.Pattern
    severity: str
    category: str
    confidence: str
    description: str


def _validate_entry(entry: dict) -> None:
    required = {"id", "pattern", "severity", "category", "confidence", "description"}
    missing = required - entry.keys()
    if missing:
        raise ValueError(f"pattern entry {entry.get('id', '<unknown>')} missing fields: {missing}")
    if entry["severity"] not in SEVERITIES:
        raise ValueError(f"pattern {entry['id']}: invalid severity {entry['severity']!r}")
    if entry["confidence"] not in ("high", "medium", "low"):
        raise ValueError(f"pattern {entry['id']}: invalid confidence {entry['confidence']!r}")


def load_signatures(path: str | Path) -> list[Signature]:
    """Load and compile the YAML signature file at ``path``."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    signatures = []
    seen_ids = set()
    for entry in raw:
        _validate_entry(entry)
        if entry["id"] in seen_ids:
            raise ValueError(f"duplicate pattern id: {entry['id']}")
        seen_ids.add(entry["id"])
        signatures.append(
            Signature(
                id=entry["id"],
                pattern=re.compile(entry["pattern"]),
                severity=entry["severity"],
                category=entry["category"],
                confidence=entry["confidence"],
                description=entry["description"],
            )
        )
    return signatures
