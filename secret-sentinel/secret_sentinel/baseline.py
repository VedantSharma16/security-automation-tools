"""Allowlisting previously-accepted findings so re-scans stay quiet on them.

Unlike a location-based baseline, fingerprints here are derived from the
secret *value* (see `scanner.compute_fingerprint`), not the file/line it was
found at. That means an accepted finding (a known test fixture, a
since-rotated credential someone chose to leave in a fixture, etc.) stays
suppressed even if the surrounding code moves or the file is renamed —
while the same secret value appearing somewhere new still gets caught.
"""

from __future__ import annotations

import json
from pathlib import Path

from .scanner import Finding


def load_allowlist(path: str | Path) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return set(data.get("fingerprints", []))


def save_allowlist(findings: list[Finding], path: str | Path) -> None:
    fingerprints = sorted({f.fingerprint for f in findings})
    Path(path).write_text(json.dumps({"fingerprints": fingerprints}, indent=2) + "\n")


def apply_allowlist(findings: list[Finding], allowlist: set[str]) -> list[Finding]:
    """Return findings whose fingerprint is not in the allowlist."""
    return [f for f in findings if f.fingerprint not in allowlist]
