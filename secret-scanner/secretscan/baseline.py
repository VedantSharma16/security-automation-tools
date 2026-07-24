"""Baseline (allowlist) handling.

A baseline records fingerprints of findings a human has already reviewed
and accepted (test fixtures, rotated/dead credentials, intentional
examples). Scans against a baseline only fail CI on *new*, un-reviewed
findings - the same workflow `detect-secrets` and similar tools use to
keep a scanner usable in a repo that already has some accepted noise.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding

BASELINE_VERSION = 1


def build_baseline(findings: list[Finding]) -> dict:
    return {
        "version": BASELINE_VERSION,
        "entries": [
            {
                "fingerprint": f.fingerprint,
                "rule_id": f.rule_id,
                "file": f.file,
            }
            for f in findings
        ],
    }


def save_baseline(findings: list[Finding], path: str) -> None:
    data = build_baseline(findings)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def load_baseline(path: str) -> set[str]:
    """Return the set of accepted fingerprints from a baseline file.

    Missing file -> empty baseline (nothing suppressed), not an error,
    so `--baseline` can point at a file that doesn't exist yet.
    """
    p = Path(path)
    if not p.exists():
        return set()
    data = json.loads(p.read_text(encoding="utf-8"))
    return {entry["fingerprint"] for entry in data.get("entries", [])}
