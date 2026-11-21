"""A small, dependency-free Bernoulli Naive Bayes classifier over word
unigrams + bigrams, used as a second detection layer next to the rule pack.

Why it exists: regex rules are precise but brittle — "set aside the
guidelines you were configured with" means the same as "ignore previous
instructions" and shares none of its keywords. A statistical model trained on
labelled examples generalises across paraphrases at the cost of being less
explainable, so the scanner treats a classifier-only hit as *review*, never
*block* (see `scanner.py`).

The decision threshold is not hand-picked: `fit_threshold` runs leave-one-out
cross-validation on the training set and chooses the lowest threshold whose
out-of-fold false-positive rate stays under a target (default 5%).
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "data" / "nb_model.json"
TOKEN_RE = re.compile(r"[a-z']+")


def featurize(text: str) -> set[str]:
    words = TOKEN_RE.findall(text.lower())
    return set(words) | {f"{a}_{b}" for a, b in zip(words, words[1:])}


@dataclass
class NaiveBayes:
    doc_counts: dict[str, int] = field(default_factory=lambda: {"malicious": 0, "benign": 0})
    feature_counts: dict[str, Counter] = field(
        default_factory=lambda: {"malicious": Counter(), "benign": Counter()})
    threshold: float = 0.0

    # -- training ------------------------------------------------------------

    def fit(self, samples: list[tuple[str, str]]) -> "NaiveBayes":
        for text, label in samples:
            self._add(text, label, +1)
        return self

    def _add(self, text: str, label: str, sign: int) -> None:
        self.doc_counts[label] += sign
        for f in featurize(text):
            self.feature_counts[label][f] += sign

    def log_odds(self, text: str) -> float:
        """log P(malicious|x) - log P(benign|x) under a Bernoulli NB restricted
        to features present in x (absent-feature terms are dropped: with a tiny
        corpus they mostly add noise)."""
        total = sum(self.doc_counts.values())
        if total == 0 or min(self.doc_counts.values()) == 0:
            return 0.0
        score = math.log(self.doc_counts["malicious"] / self.doc_counts["benign"])
        for f in featurize(text):
            m, b = self.feature_counts["malicious"][f], self.feature_counts["benign"][f]
            if m == 0 and b == 0:
                continue
            p_m = (m + 1) / (self.doc_counts["malicious"] + 2)
            p_b = (b + 1) / (self.doc_counts["benign"] + 2)
            score += math.log(p_m / p_b)
        return score

    def probability(self, text: str) -> float:
        z = max(-50.0, min(50.0, self.log_odds(text) - self.threshold))
        return 1.0 / (1.0 + math.exp(-z))

    def is_malicious(self, text: str) -> bool:
        return self.log_odds(text) >= self.threshold

    # -- threshold calibration ----------------------------------------------

    def leave_one_out_scores(self, samples: list[tuple[str, str]]) -> list[tuple[float, str]]:
        scores = []
        for text, label in samples:
            self._add(text, label, -1)
            scores.append((self.log_odds(text), label))
            self._add(text, label, +1)
        return scores

    def fit_threshold(self, samples: list[tuple[str, str]], max_fpr: float = 0.05) -> float:
        scores = self.leave_one_out_scores(samples)
        benign = sorted(s for s, lbl in scores if lbl == "benign")
        if not benign:
            self.threshold = 0.0
            return self.threshold
        allowed_fp = math.floor(max_fpr * len(benign))
        # Threshold sits just above the (allowed_fp+1)-th highest benign score.
        cutoff = benign[-(allowed_fp + 1)]
        self.threshold = round(max(cutoff + 1e-6, 0.0), 6)
        return self.threshold

    # -- persistence ---------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "type": "bernoulli_nb_uni_bigram",
            "threshold": self.threshold,
            "doc_counts": self.doc_counts,
            "feature_counts": {k: dict(v) for k, v in self.feature_counts.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NaiveBayes":
        return cls(
            doc_counts=dict(data["doc_counts"]),
            feature_counts={k: Counter(v) for k, v in data["feature_counts"].items()},
            threshold=float(data["threshold"]),
        )

    def save(self, path: str | Path = DEFAULT_MODEL_PATH) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path = DEFAULT_MODEL_PATH) -> "NaiveBayes":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def load_corpus(path: str | Path) -> list[dict]:
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def train_from_corpus(path: str | Path, max_fpr: float = 0.05) -> NaiveBayes:
    samples = [(r["text"], r["label"]) for r in load_corpus(path)]
    model = NaiveBayes().fit(samples)
    model.fit_threshold(samples, max_fpr=max_fpr)
    return model
