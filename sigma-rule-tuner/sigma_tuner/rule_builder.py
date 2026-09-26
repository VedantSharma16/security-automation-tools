"""Assemble a full Sigma-style rule dict from a technique KB entry and one of its variants."""

from __future__ import annotations

import copy
from typing import Any


def build_rule(technique: dict, technique_id: str, variant: dict) -> dict[str, Any]:
    """Combine a technique's shared metadata with one variant's detection logic."""
    return {
        "title": f"{technique['name']} ({variant['id']})",
        "id": f"{technique_id.lower()}-{variant['id']}",
        "status": "experimental",
        "description": variant.get("rationale", ""),
        "references": list(technique.get("references", [])),
        "tags": [f"attack.{tactic}" for tactic in technique.get("tactics", [])]
        + [f"attack.{technique_id.lower()}"],
        "logsource": copy.deepcopy(technique.get("logsource", {})),
        "detection": copy.deepcopy(variant["detection"]),
        "falsepositives": list(technique.get("falsepositives", [])),
        "level": variant.get("level", technique.get("level_default", "medium")),
    }
