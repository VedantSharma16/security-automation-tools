"""A minimal local retrieval layer over a MITRE ATT&CK technique reference set.

This is intentionally simple ("RAG-lite"): term-overlap scoring instead of
vector embeddings. It's enough to surface the 1-2 most relevant techniques
for a given alert without needing an embedding model or vector store, and
it stays fully deterministic and dependency-free for testing.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

_DEFAULT_KB_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre_attack_kb.json"
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


class KnowledgeBase:
    def __init__(self, entries: list[dict]):
        self.entries = entries

    @classmethod
    def load(cls, path: str | Path | None = None) -> "KnowledgeBase":
        resolved = Path(path) if path else _DEFAULT_KB_PATH
        entries = json.loads(resolved.read_text(encoding="utf-8"))
        return cls(entries)

    def retrieve(self, query: str, top_k: int = 2) -> list[dict]:
        """Return the top_k entries with the highest token-overlap score
        against the query. Entries with zero overlap are excluded.
        """
        query_terms = Counter(_tokenize(query))
        scored: list[tuple[int, dict]] = []
        for entry in self.entries:
            doc_text = " ".join(
                [
                    entry["technique_id"],
                    entry["name"],
                    entry["description"],
                    " ".join(entry.get("keywords", [])),
                ]
            )
            doc_terms = Counter(_tokenize(doc_text))
            score = sum(min(count, doc_terms.get(term, 0)) for term, count in query_terms.items())
            if score > 0:
                scored.append((score, entry))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [entry for _, entry in scored[:top_k]]
