"""Retrieves the MITRE ATT&CK techniques most relevant to a given alert (the "R" in RAG)."""

from typing import List

from .knowledge_base import Technique
from .models import TechniqueMatch
from .vectorizer import TfidfVectorizer, cosine_similarity


class TechniqueRetriever:
    def __init__(self, techniques: List[Technique]):
        if not techniques:
            raise ValueError("TechniqueRetriever requires at least one technique")
        self.techniques = techniques
        self.vectorizer = TfidfVectorizer().fit([t.corpus_text() for t in techniques])
        self._vectors = [self.vectorizer.transform(t.corpus_text()) for t in techniques]

    def retrieve(self, query_text: str, top_k: int = 3) -> List[TechniqueMatch]:
        query_vec = self.vectorizer.transform(query_text)
        scored = [
            TechniqueMatch(
                technique_id=t.id,
                name=t.name,
                tactic=t.tactic,
                score=cosine_similarity(query_vec, vec),
            )
            for t, vec in zip(self.techniques, self._vectors)
        ]
        scored.sort(key=lambda m: m.score, reverse=True)
        return scored[:top_k]
