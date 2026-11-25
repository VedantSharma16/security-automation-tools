"""Red-team evaluation harness: measure the guard against a labelled corpus.

A detector without numbers is a guess. ``evaluate`` replays a JSONL corpus
(``{"id", "label": "attack"|"benign", "source", "category", "text"}``) through
the guard and reports precision / recall / F1, false-positive rate, per-
category recall and every miss, so rule changes can be judged by data rather
than by eyeballing a couple of examples. A sample counts as *detected* when
the verdict is ``flag`` or ``block`` (``--strict`` counts only ``block``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .guard import Guard


@dataclass
class EvalReport:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    per_category: dict[str, list[int]] = field(default_factory=dict)  # category -> [detected, total]
    misses: list[dict] = field(default_factory=list)
    false_positives: list[dict] = field(default_factory=list)

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
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    def to_dict(self) -> dict:
        return {
            "confusion": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "false_positive_rate": round(self.fpr, 3),
            "per_category_recall": {k: {"detected": v[0], "total": v[1]} for k, v in sorted(self.per_category.items())},
            "misses": self.misses,
            "false_positives": self.false_positives,
        }

    def render(self) -> str:
        lines = [
            "Prompt-injection guard evaluation",
            "=" * 34,
            f"samples: {self.tp + self.fp + self.tn + self.fn}   attacks: {self.tp + self.fn}   benign: {self.tn + self.fp}",
            f"precision {self.precision:.3f}  recall {self.recall:.3f}  F1 {self.f1:.3f}  FPR {self.fpr:.3f}",
            f"confusion  TP={self.tp} FP={self.fp} TN={self.tn} FN={self.fn}",
            "",
            "per-category recall:",
        ]
        for cat, (hit, total) in sorted(self.per_category.items()):
            lines.append(f"  {cat:<22} {hit}/{total}")
        if self.misses:
            lines += ["", "missed attacks:"] + [f"  {m['id']} [{m['category']}] score={m['score']}: {m['text'][:70]!r}" for m in self.misses]
        if self.false_positives:
            lines += ["", "false positives:"] + [
                f"  {m['id']} score={m['score']} {m['categories']}: {m['text'][:70]!r}" for m in self.false_positives]
        return "\n".join(lines)


def load_corpus(path: str | Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("label") not in ("attack", "benign") or "text" not in row:
                raise ValueError(f"{path}:{lineno}: each row needs 'text' and label 'attack'|'benign'")
            rows.append(row)
    return rows


def evaluate(rows: list[dict], guard: Guard | None = None, strict: bool = False) -> EvalReport:
    guard = guard or Guard()
    hits = {"block"} if strict else {"flag", "block"}
    report = EvalReport()
    for row in rows:
        result = guard.scan_input(row["text"], row.get("source", "user"))
        detected = result.verdict in hits
        record = {"id": row.get("id"), "category": row.get("category"), "score": round(result.score, 3),
                  "categories": result.categories, "text": row["text"]}
        if row["label"] == "attack":
            bucket = report.per_category.setdefault(row.get("category") or "uncategorised", [0, 0])
            bucket[1] += 1
            if detected:
                report.tp += 1
                bucket[0] += 1
            else:
                report.fn += 1
                report.misses.append(record)
        elif detected:
            report.fp += 1
            report.false_positives.append(record)
        else:
            report.tn += 1
    return report
