"""A small retrieval-augmented-generation (RAG) component.

Indexes a bundled subset of MITRE ATT&CK technique descriptions and
retrieves the most relevant ones for a piece of alert text using TF-IDF
weighting and cosine similarity. Implemented in pure Python (no numpy /
scikit-learn) so the retrieval logic itself stays inspectable — the point
of this module is to demonstrate understanding of how RAG retrieval
actually works, not to wrap a vector-database SDK.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TECHNIQUES_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre_attack_techniques.json"

_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]{1,}")
_STOPWORDS = {
    "the", "and", "or", "to", "of", "in", "on", "for", "with", "as", "by",
    "is", "are", "may", "an", "a", "that", "this", "such", "into",
    "be", "their", "at", "from",
}


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text) if t.lower() not in _STOPWORDS]


@dataclass
class Technique:
    id: str
    name: str
    tactic: str
    text: str

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "tactic": self.tactic, "text": self.text}


def _load_techniques(path: Path | str) -> list[Technique]:
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    return [
        Technique(id=t["id"], name=t["name"], tactic=t["tactic"], text=t["text"])
        for t in raw.get("techniques", [])
    ]


class TechniqueKnowledgeBase:
    """TF-IDF index over ATT&CK technique descriptions for RAG retrieval."""

    def __init__(self, techniques: list[Technique]):
        self.techniques = techniques
        self._doc_tokens = [_tokenize(f"{t.name} {t.text}") for t in techniques]
        self._doc_freq = self._compute_doc_frequency(self._doc_tokens)
        self._idf = self._compute_idf(self._doc_freq, len(techniques))
        self._doc_vectors = [self._vectorize(tokens) for tokens in self._doc_tokens]

    @classmethod
    def from_file(cls, path: Path | str = DEFAULT_TECHNIQUES_PATH) -> "TechniqueKnowledgeBase":
        return cls(_load_techniques(path))

    @staticmethod
    def _compute_doc_frequency(doc_tokens: list[list[str]]) -> Counter:
        df: Counter = Counter()
        for tokens in doc_tokens:
            df.update(set(tokens))
        return df

    @staticmethod
    def _compute_idf(doc_freq: Counter, n_docs: int) -> dict[str, float]:
        # Smoothed idf: log((1 + N) / (1 + df)) + 1, avoids division by zero
        # and keeps weights positive for terms present in every document.
        return {
            term: math.log((1 + n_docs) / (1 + df)) + 1.0
            for term, df in doc_freq.items()
        }

    def _vectorize(self, tokens: list[str]) -> dict[str, float]:
        if not tokens:
            return {}
        tf = Counter(tokens)
        max_freq = max(tf.values())
        vector = {
            term: (0.5 + 0.5 * count / max_freq) * self._idf.get(term, 0.0)
            for term, count in tf.items()
        }
        norm = math.sqrt(sum(w * w for w in vector.values())) or 1.0
        return {term: w / norm for term, w in vector.items()}

    @staticmethod
    def _cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
        if not vec_a or not vec_b:
            return 0.0
        shorter, longer = (vec_a, vec_b) if len(vec_a) < len(vec_b) else (vec_b, vec_a)
        return sum(weight * longer.get(term, 0.0) for term, weight in shorter.items())

    def query(self, text: str, top_k: int = 3, min_score: float = 0.0) -> list[tuple[Technique, float]]:
        """Return up to ``top_k`` techniques most similar to ``text``."""
        query_vector = self._vectorize(_tokenize(text))
        scored = [
            (technique, self._cosine_similarity(query_vector, doc_vector))
            for technique, doc_vector in zip(self.techniques, self._doc_vectors)
        ]
        scored = [pair for pair in scored if pair[1] > min_score]
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:top_k]
