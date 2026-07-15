"""A minimal, dependency-free TF-IDF vectorizer and cosine similarity.

Implemented from scratch (stdlib only) rather than pulling in scikit-learn,
so the retrieval pipeline stays auditable and trivial to install in any
SOC/analyst environment.
"""

import math
import re
from collections import Counter
from typing import Dict, List

_TOKEN_RE = re.compile(r"[a-zA-Z0-9_./\\-]+")
_STOPWORDS = {"the", "a", "an", "of", "to", "in", "on", "for", "and", "or", "is", "with", "by", "from"}


def tokenize(text: str) -> List[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text) if t.lower() not in _STOPWORDS and len(t) > 1]


class TfidfVectorizer:
    """Fit on a corpus of documents, then transform new text into sparse TF-IDF vectors."""

    def __init__(self) -> None:
        self._idf: Dict[str, float] = {}
        self._fitted = False

    def fit(self, documents: List[str]) -> "TfidfVectorizer":
        n_docs = len(documents)
        doc_freq: Counter = Counter()
        for doc in documents:
            for term in set(tokenize(doc)):
                doc_freq[term] += 1
        # Smoothed IDF, same shape as scikit-learn's default: ln((n+1)/(df+1)) + 1
        self._idf = {term: math.log((n_docs + 1) / (freq + 1)) + 1 for term, freq in doc_freq.items()}
        self._fitted = True
        return self

    def transform(self, text: str) -> Dict[str, float]:
        if not self._fitted:
            raise RuntimeError("TfidfVectorizer must be fit() before transform()")
        counts = Counter(tokenize(text))
        total = sum(counts.values()) or 1
        default_idf = math.log(2)  # fallback for terms unseen during fit
        return {term: (count / total) * self._idf.get(term, default_idf) for term, count in counts.items()}


def cosine_similarity(vec_a: Dict[str, float], vec_b: Dict[str, float]) -> float:
    if not vec_a or not vec_b:
        return 0.0
    common = set(vec_a) & set(vec_b)
    dot = sum(vec_a[t] * vec_b[t] for t in common)
    norm_a = math.sqrt(sum(v * v for v in vec_a.values()))
    norm_b = math.sqrt(sum(v * v for v in vec_b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
