"""Loader for the bundled MITRE ATT&CK technique knowledge base.

Each technique entry carries an ordered list of rule *variants*, from most
permissive to least. The variants embody real detection-engineering
judgment (what a human analyst would try, in what order) -- the automated
part, done by :mod:`sigma_tuner.tuner`, is *selecting* the variant that best
fits the labeled telemetry it's given, not inventing detection logic from
scratch.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_KB_PATH = Path(__file__).resolve().parent.parent / "data" / "technique_kb.json"


@lru_cache(maxsize=1)
def _load() -> dict:
    with open(_KB_PATH, encoding="utf-8") as f:
        return json.load(f)


def list_techniques() -> list[str]:
    """Return all known ATT&CK technique IDs, sorted."""
    return sorted(_load().keys())


def get_technique(technique_id: str) -> dict:
    """Return the KB entry for `technique_id`, or raise KeyError with the known IDs."""
    kb = _load()
    try:
        return kb[technique_id]
    except KeyError:
        known = ", ".join(sorted(kb.keys()))
        raise KeyError(f"unknown technique {technique_id!r}; known techniques: {known}") from None
