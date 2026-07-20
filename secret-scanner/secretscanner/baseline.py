"""Baseline snapshotting so previously-accepted findings don't re-alert.

Mirrors how gitleaks/trufflehog baselines work: a team runs a scan, triages
every hit (fixes real leaks, accepts known/rotated or test-only ones), and
records the survivors' fingerprints. Future scans only report *new*
findings, which is what makes it practical to run this in CI without
someone re-triaging the same accepted findings on every run.
"""

from __future__ import annotations

import json
from pathlib import Path


def save_baseline(findings: list, path) -> None:
    fingerprints = sorted({f.fingerprint() for f in findings})
    Path(path).write_text(json.dumps({"fingerprints": fingerprints}, indent=2))


def load_baseline(path) -> set:
    data = json.loads(Path(path).read_text())
    return set(data.get("fingerprints", []))


def filter_new(findings: list, baseline: set) -> list:
    """Return only findings whose fingerprint is not in the baseline."""
    return [f for f in findings if f.fingerprint() not in baseline]
