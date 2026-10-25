"""Evaluate the detector against a labelled corpus (JSONL).

Each line: {"text": str, "malicious": bool, "category": str}. A sample is
predicted malicious when the verdict is ``block`` or ``suspicious``.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .detector import scan


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    missed: list[str] = field(default_factory=list)
    false_alarms: list[str] = field(default_factory=list)
    recall_by_category: dict[str, float] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 3), "recall": round(self.recall, 3),
            "f1": round(self.f1, 3), "accuracy": round(self.accuracy, 3),
            "recall_by_category": self.recall_by_category,
            "missed": self.missed, "false_alarms": self.false_alarms,
        }


def load_corpus(path: str | Path) -> list[dict]:
    rows = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if "text" not in row or "malicious" not in row:
            raise ValueError(f"{path}:{n}: sample needs 'text' and 'malicious'")
        rows.append(row)
    return rows


def evaluate(samples: list[dict]) -> Metrics:
    m = Metrics()
    cat_total: dict[str, int] = defaultdict(int)
    cat_hit: dict[str, int] = defaultdict(int)
    for s in samples:
        flagged = scan(s["text"]).label != "allow"
        if s["malicious"]:
            cat = s.get("category", "unknown")
            cat_total[cat] += 1
            if flagged:
                m.tp += 1
                cat_hit[cat] += 1
            else:
                m.fn += 1
                m.missed.append(s["text"][:80])
        elif flagged:
            m.fp += 1
            m.false_alarms.append(s["text"][:80])
        else:
            m.tn += 1
    m.recall_by_category = {c: round(cat_hit[c] / t, 3) for c, t in sorted(cat_total.items())}
    return m
