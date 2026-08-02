"""Baseline files for suppressing previously-reviewed findings.

Mirrors the workflow of tools like gitleaks/detect-secrets: after a human
reviews a scan and confirms certain findings are false positives (test
fixtures, rotated/dummy credentials, intentional examples in docs), those
findings' fingerprints get written to a baseline file. Future scans still
run every detector, but drop anything whose fingerprint is already known,
so the report only surfaces genuinely new findings.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_baseline(path) -> set:
    """Load a baseline file, returning the set of suppressed fingerprints.

    A missing file is treated as an empty baseline rather than an error, so
    ``--baseline`` can be pointed at a not-yet-created file.
    """
    path = Path(path)
    if not path.exists():
        return set()
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return set(data.get("ignored_fingerprints", []))


def save_baseline(findings: list, path) -> None:
    """Write the fingerprints of ``findings`` to a baseline file.

    Only fingerprints are persisted -- never file contents or previews --
    so a baseline file is safe to commit alongside the source it covers.
    """
    fingerprints = sorted({f.fingerprint for f in findings})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"ignored_fingerprints": fingerprints}, fh, indent=2)
        fh.write("\n")


def apply_baseline(findings: list, baseline: set) -> list:
    """Filter out findings whose fingerprint is present in ``baseline``."""
    return [f for f in findings if f.fingerprint not in baseline]
