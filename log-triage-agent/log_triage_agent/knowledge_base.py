"""A tiny local retrieval layer over a MITRE ATT&CK technique knowledge base.

This is deliberately dependency-free: relevance is scored with token-overlap
(Jaccard similarity) rather than embeddings, so the whole pipeline runs with
zero external services or API keys. The retrieval/generation split still
mirrors a real RAG pipeline -- swap `_score` for an embedding-based similarity
function and everything downstream (reporter.py) is unaffected.
"""

import json
import os
import re
from dataclasses import dataclass
from typing import List

_DEFAULT_KB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "attack_techniques.json"
)

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> set:
    return set(_TOKEN_RE.findall(text.lower()))


@dataclass
class Technique:
    id: str
    name: str
    tactic: str
    finding_types: List[str]
    description: str
    url: str
    score: float = 0.0


class AttackKnowledgeBase:
    """Loads ATT&CK technique records and retrieves the most relevant ones
    for a given finding type / query text."""

    def __init__(self, path: str = _DEFAULT_KB_PATH):
        with open(path, "r", encoding="utf-8") as f:
            self._records = json.load(f)

    def _score(self, query_tokens: set, technique: dict) -> float:
        doc_tokens = _tokenize(technique["name"] + " " + technique["description"])
        if not query_tokens or not doc_tokens:
            return 0.0
        overlap = query_tokens & doc_tokens
        union = query_tokens | doc_tokens
        return len(overlap) / len(union)

    def retrieve_for_finding(self, finding_type: str, query_text: str = "", top_k: int = 3) -> List[Technique]:
        """Retrieve techniques tagged for `finding_type`, ranked by textual
        similarity to `query_text` (typically the finding's summary)."""
        query_tokens = _tokenize(finding_type + " " + query_text)
        candidates = [r for r in self._records if finding_type in r.get("finding_types", [])]
        scored = [
            Technique(**{k: v for k, v in r.items() if k != "score"}, score=self._score(query_tokens, r))
            for r in candidates
        ]
        scored.sort(key=lambda t: t.score, reverse=True)
        return scored[:top_k]

    def search(self, query: str, top_k: int = 3) -> List[Technique]:
        """Free-text search across the whole knowledge base, independent of
        finding type -- useful for ad hoc analyst lookups from the CLI."""
        query_tokens = _tokenize(query)
        scored = [
            Technique(**{k: v for k, v in r.items() if k != "score"}, score=self._score(query_tokens, r))
            for r in self._records
        ]
        scored.sort(key=lambda t: t.score, reverse=True)
        return [t for t in scored[:top_k] if t.score > 0]
