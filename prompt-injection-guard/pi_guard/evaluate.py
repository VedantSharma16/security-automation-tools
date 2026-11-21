"""Measure detector quality against a labelled JSONL corpus.

Each line: {"text": ..., "source": "user"|"retrieved",
            "label": "malicious"|"benign", "category": ...}

A sample counts as *flagged* when the verdict is `review` or `block` — i.e.
anything that would not be passed straight through to the model.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .classifier import load_corpus
from .scanner import InjectionScanner


@dataclass
class EvalReport:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    per_category: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))
    misses: list[dict] = field(default_factory=list)
    false_positives: list[dict] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0

    def to_dict(self) -> dict:
        return {
            "confusion": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "false_positive_rate": round(self.fpr, 3),
            "recall_by_category": {
                cat: f"{hit}/{total}" for cat, (hit, total) in sorted(self.per_category.items())
            },
            "misses": self.misses,
            "false_positives": self.false_positives,
        }


def evaluate(corpus_path: str | Path, scanner: InjectionScanner | None = None) -> EvalReport:
    scanner = scanner or InjectionScanner()
    report = EvalReport()
    for row in load_corpus(corpus_path):
        result = scanner.scan(row["text"], source=row.get("source", "user"))
        flagged = result.verdict != "allow"
        malicious = row["label"] == "malicious"
        summary = {"text": row["text"][:100], "score": result.score, "verdict": result.verdict,
                   "rules": [f.rule_id for f in result.findings]}
        if malicious:
            cat = report.per_category[row.get("category", "unknown")]
            cat[1] += 1
            if flagged:
                report.tp += 1
                cat[0] += 1
            else:
                report.fn += 1
                report.misses.append(summary)
        elif flagged:
            report.fp += 1
            report.false_positives.append(summary)
        else:
            report.tn += 1
    return report


def format_report(name: str, report: EvalReport) -> str:
    lines = [
        f"== {name} ==",
        f"  precision {report.precision:.2f}  recall {report.recall:.2f}  "
        f"F1 {report.f1:.2f}  FPR {report.fpr:.2f}",
        f"  confusion: TP={report.tp} FP={report.fp} TN={report.tn} FN={report.fn}",
    ]
    for cat, (hit, total) in sorted(report.per_category.items()):
        lines.append(f"    {cat:<22} {hit}/{total}")
    for miss in report.misses:
        lines.append(f"  MISS  [{miss['score']:>3}] {miss['text']}")
    for fp in report.false_positives:
        lines.append(f"  FP    [{fp['score']:>3}] {fp['text']}")
    return "\n".join(lines)
