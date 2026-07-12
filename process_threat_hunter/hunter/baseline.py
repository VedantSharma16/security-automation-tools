"""Baseline snapshotting so newly-appeared processes can be flagged.

This mirrors a common blue-team technique: record what "normal" looks like
on a known-good host, then highlight anything that shows up later that
wasn't part of that baseline, independent of whether it also trips a
signature rule.
"""

from __future__ import annotations

import json
from pathlib import Path


def save_baseline(processes: list, path) -> None:
    fingerprints = sorted({p.fingerprint() for p in processes})
    Path(path).write_text(json.dumps({"fingerprints": fingerprints}, indent=2))


def load_baseline(path) -> set:
    data = json.loads(Path(path).read_text())
    return set(data.get("fingerprints", []))


def diff_baseline(processes: list, baseline: set) -> list:
    """Return processes whose fingerprint was not present in the baseline."""
    return [p for p in processes if p.fingerprint() not in baseline]
