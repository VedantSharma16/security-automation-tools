"""A from-scratch multinomial Naive Bayes classifier for injection-like text.

Signatures are precise but brittle: they miss paraphrases. A small
statistical model trained on labelled examples generalises across wording
("please set aside the guidance you were given") at the cost of some
precision. :mod:`prompt_firewall.firewall` fuses both signals.

Implemented with the standard library only so the model is fully
inspectable: :meth:`NaiveBayes.top_features` explains which tokens drove a
prediction, which matters when an analyst has to justify a block.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

_TOKEN = re.compile(r"[a-z][a-z']+")
_STOPWORDS = frozenset(
    "a an the and or of to in on for is are be it this that with as at by from i me my we our".split()
)


def tokenize(text: str) -> list[str]:
    words = [w for w in _TOKEN.findall(text.lower()) if w not in _STOPWORDS]
    bigrams = [f"{a}_{b}" for a, b in zip(words, words[1:])]
    return words + bigrams


@dataclass
class NaiveBayes:
    alpha: float = 1.0
    class_counts: Counter = field(default_factory=Counter)
    token_counts: dict[int, Counter] = field(default_factory=lambda: {0: Counter(), 1: Counter()})
    vocabulary: set[str] = field(default_factory=set)

    def fit(self, texts: list[str], labels: list[int]) -> "NaiveBayes":
        if len(texts) != len(labels):
            raise ValueError("texts and labels must be the same length")
        for text, label in zip(texts, labels):
            tokens = tokenize(text)
            self.class_counts[label] += 1
            self.token_counts[label].update(tokens)
            self.vocabulary.update(tokens)
        return self

    @property
    def is_trained(self) -> bool:
        return bool(self.class_counts[0] and self.class_counts[1])

    def _log_likelihood(self, token: str, label: int) -> float:
        total = sum(self.token_counts[label].values())
        return math.log(
            (self.token_counts[label][token] + self.alpha) / (total + self.alpha * len(self.vocabulary))
        )

    def predict_proba(self, text: str) -> float:
        """Probability that ``text`` is malicious (class 1)."""
        if not self.is_trained:
            return 0.0
        tokens = [t for t in tokenize(text) if t in self.vocabulary]
        if not tokens:
            return 0.0  # nothing we have seen before: no evidence either way, default to benign
        n = sum(self.class_counts.values())
        scores = {}
        for label in (0, 1):
            scores[label] = math.log(self.class_counts[label] / n) + sum(
                self._log_likelihood(t, label) for t in tokens
            )
        # Numerically stable softmax over two classes.
        m = max(scores.values())
        e0, e1 = math.exp(scores[0] - m), math.exp(scores[1] - m)
        return e1 / (e0 + e1)

    def top_features(self, text: str, k: int = 5) -> list[tuple[str, float]]:
        """Tokens in ``text`` with the largest malicious-vs-benign log-odds."""
        contributions = {
            t: self._log_likelihood(t, 1) - self._log_likelihood(t, 0)
            for t in set(tokenize(text))
            if t in self.vocabulary
        }
        return sorted(contributions.items(), key=lambda kv: kv[1], reverse=True)[:k]


def load_jsonl(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


DEFAULT_TRAIN_PATH = Path(__file__).resolve().parent.parent / "data" / "train.jsonl"


def train_default(path: str | Path = DEFAULT_TRAIN_PATH) -> NaiveBayes:
    rows = load_jsonl(path)
    return NaiveBayes().fit([r["text"] for r in rows], [int(r["label"]) for r in rows])
