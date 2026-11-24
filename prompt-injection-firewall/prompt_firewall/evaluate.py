"""Evaluation harness: measure the detector against a labelled corpus.

A detection rule set without measured precision/recall is a guess. This
module runs the scanner over a JSONL corpus of labelled samples (attacks
*and* deliberately tricky benign text) and reports a confusion matrix,
precision/recall/F1, per-category recall and every miss, so rule changes can
be judged by numbers instead of vibes.

JSONL record format::

    {"text": "...", "source": "user|retrieved|tool_output",
     "label": 1, "category": "instruction_override"}

``label`` is 1 for injection, 0 for benign.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .scanner import Scanner


@dataclass
class EvalReport:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    per_category: dict[str, dict[str, int]] = field(default_factory=dict)
    false_positives: list[dict] = field(default_factory=list)
    false_negatives: list[dict] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

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
        return (self.tp + self.tn) / self.total if self.total else 0.0

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "confusion": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "per_category": self.per_category,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
        }

    def render(self) -> str:
        lines = [
            f"Samples: {self.total}",
            f"Confusion: TP={self.tp} FP={self.fp} TN={self.tn} FN={self.fn}",
            f"Precision {self.precision:.3f} | Recall {self.recall:.3f} | "
            f"F1 {self.f1:.3f} | Accuracy {self.accuracy:.3f}",
            "",
            "Per-category detection (attacks) / pass-through (benign):",
        ]
        for cat, c in sorted(self.per_category.items()):
            lines.append(f"  {cat:<22} {c['correct']}/{c['total']}")
        for title, items in (("False positives", self.false_positives), ("False negatives", self.false_negatives)):
            if items:
                lines.append("")
                lines.append(f"{title}:")
                for item in items:
                    lines.append(f"  [{item['source']}] score={item['score']} {item['text'][:90]!r}")
        return "\n".join(lines)


def load_corpus(path: str | Path) -> list[dict]:
    samples = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        record = json.loads(line)
        if record.get("label") not in (0, 1) or "text" not in record:
            raise ValueError(f"line {n}: needs 'text' and label 0/1")
        samples.append(record)
    return samples


def evaluate(samples: list[dict], scanner: Scanner | None = None) -> EvalReport:
    scanner = scanner or Scanner()
    report = EvalReport()
    per_cat: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "correct": 0})

    for sample in samples:
        source = sample.get("source", "user")
        result = scanner.scan(sample["text"], source=source, sanitize=False)
        predicted = 1 if result.flagged else 0
        label = sample["label"]
        category = sample.get("category") or ("benign" if label == 0 else "uncategorised")

        per_cat[category]["total"] += 1
        if predicted == label:
            per_cat[category]["correct"] += 1

        brief = {"text": sample["text"], "source": source, "score": result.score,
                 "rules": [f.rule_id for f in result.findings]}
        if label and predicted:
            report.tp += 1
        elif label and not predicted:
            report.fn += 1
            report.false_negatives.append(brief)
        elif not label and predicted:
            report.fp += 1
            report.false_positives.append(brief)
        else:
            report.tn += 1

    report.per_category = dict(per_cat)
    return report
