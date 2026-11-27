"""Evaluation harness: measure the guard against a labeled corpus.

A detector without a measured false-positive rate is a liability, not a
control. This module scores the guard on a JSONL corpus of
``{"id", "text", "source", "label": "injection"|"benign", "category"}`` rows
and reports precision / recall / F1, per-category recall, and every miss and
false alarm so rules can be tuned against evidence instead of intuition.

A sample counts as *detected* when the verdict is FLAG or BLOCK — FLAG means
the content is sanitized and spotlighted before it reaches the model, which
is a real mitigation, not a pass.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .guard import Guard, Verdict


@dataclass
class EvalReport:
    total: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    blocked: int = 0
    flagged: int = 0
    per_category: dict[str, dict[str, int]] = field(default_factory=dict)
    false_negatives: list[dict] = field(default_factory=list)
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
    def false_positive_rate(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "confusion_matrix": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "verdicts": {"block": self.blocked, "flag": self.flagged},
            "per_category_recall": {
                cat: {**counts, "recall": round(counts["detected"] / counts["total"], 3)}
                for cat, counts in sorted(self.per_category.items())
            },
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
        }


def load_corpus(path: str | Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("label") not in {"injection", "benign"}:
                raise ValueError(f"line {line_no}: label must be 'injection' or 'benign'")
            rows.append(row)
    return rows


def evaluate(rows: list[dict], guard: Guard | None = None) -> EvalReport:
    guard = guard or Guard()
    report = EvalReport()
    per_cat: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "detected": 0})

    for row in rows:
        result = guard.scan(row["text"], row.get("source", "user"))
        detected = result.verdict is not Verdict.ALLOW
        report.total += 1
        report.blocked += result.verdict is Verdict.BLOCK
        report.flagged += result.verdict is Verdict.FLAG
        summary = {
            "id": row.get("id"),
            "source": result.source.value,
            "verdict": result.verdict.value,
            "risk_score": result.risk_score,
            "rules": [d.rule_id for d in result.detections],
            "text": row["text"][:120],
        }
        if row["label"] == "injection":
            cat = per_cat[row.get("category", "uncategorized")]
            cat["total"] += 1
            if detected:
                report.tp += 1
                cat["detected"] += 1
            else:
                report.fn += 1
                report.false_negatives.append(summary)
        else:
            if detected:
                report.fp += 1
                report.false_positives.append(summary)
            else:
                report.tn += 1

    report.per_category = dict(per_cat)
    return report


def format_report(report: EvalReport) -> str:
    d = report.to_dict()
    cm = d["confusion_matrix"]
    lines = [
        f"Samples: {d['total']}   precision={d['precision']:.3f}  recall={d['recall']:.3f}  "
        f"F1={d['f1']:.3f}  FPR={d['false_positive_rate']:.3f}",
        f"Confusion matrix: TP={cm['tp']} FP={cm['fp']} TN={cm['tn']} FN={cm['fn']}   "
        f"(blocked={d['verdicts']['block']}, flagged={d['verdicts']['flag']})",
        "",
        "Recall by attack category:",
    ]
    for cat, stats in d["per_category_recall"].items():
        lines.append(f"  {cat:<22} {stats['detected']:>2}/{stats['total']:<2}  {stats['recall']:.2f}")
    if d["false_negatives"]:
        lines += ["", "Missed attacks (false negatives):"]
        lines += [f"  {fn['id']} [{fn['source']}] score={fn['risk_score']}: {fn['text']}" for fn in d["false_negatives"]]
    if d["false_positives"]:
        lines += ["", "False alarms (false positives):"]
        lines += [f"  {fp['id']} [{fp['source']}] {fp['verdict']} score={fp['risk_score']} {fp['rules']}: {fp['text']}"
                  for fp in d["false_positives"]]
    return "\n".join(lines)
