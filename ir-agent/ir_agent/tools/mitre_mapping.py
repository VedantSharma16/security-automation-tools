"""Map free-text incident context to MITRE ATT&CK techniques via keyword scoring.

This deliberately uses plain keyword overlap rather than the TF-IDF/cosine RAG
approach in ``../ioc-triage-assistant`` — the two projects showcase different
retrieval techniques against the same kind of ATT&CK dataset.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "mitre_attack_techniques.json"

_WORD_RE = re.compile(r"[a-z0-9]+")


@lru_cache(maxsize=1)
def _load_techniques(path: str = str(_DATA_PATH)) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def map_attack_techniques(text: str, top_k: int = 3) -> list[dict]:
    """Score every known technique by keyword-phrase overlap with ``text``.

    Returns up to ``top_k`` techniques with score > 0, sorted by descending
    score, each annotated with the specific keyword phrases that matched.
    """
    lowered = text.lower()
    scored = []
    for technique in _load_techniques():
        matched = [kw for kw in technique["keywords"] if kw in lowered]
        if matched:
            scored.append(
                {
                    "id": technique["id"],
                    "name": technique["name"],
                    "tactic": technique["tactic"],
                    "score": len(matched),
                    "matched_keywords": matched,
                }
            )
    scored.sort(key=lambda t: t["score"], reverse=True)
    return scored[:top_k]
