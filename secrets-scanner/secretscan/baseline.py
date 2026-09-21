"""Baseline (allowlist) support for suppressing known/accepted findings.

Mirrors the workflow of tools like gitleaks/trufflehog: run a scan once,
review the findings, and `--create-baseline` to snapshot the fingerprints of
the ones you've decided are fine (test fixtures, rotated/expired keys kept
in history on purpose, etc). Future scans skip anything in the baseline and
only fail CI on *new* findings.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_baseline(path: Path) -> set:
    if not path.exists():
        return set()
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return set(data.get("fingerprints", []))


def save_baseline(findings: list, path: Path) -> None:
    payload = {
        "fingerprints": sorted({f.fingerprint for f in findings}),
        "finding_count": len(findings),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")


def apply_baseline(findings: list, baseline: set) -> list:
    """Return only the findings whose fingerprint is *not* in the baseline."""
    if not baseline:
        return list(findings)
    return [f for f in findings if f.fingerprint not in baseline]
