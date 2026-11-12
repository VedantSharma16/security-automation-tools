"""Evaluation harness: measure the detector against a labeled dataset.

A guardrail without numbers is a guess. This module runs the scanner over a
JSONL dataset of labeled samples and reports precision / recall / F1, a
confusion matrix, per-category recall, the false positives and false
negatives themselves (so regressions are debuggable), and a threshold sweep
showing the precision/recall trade-off an operator is choosing between.

Dataset format — one JSON object per line:
    {"text": "...", "label": "malicious"|"benign", "source": "user"|"retrieved"|"tool",
     "category": "instruction-override", "note": "optional"}
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .scanner import DEFAULT_BLOCK_THRESHOLD, DEFAULT_REVIEW_THRESHOLD, scan_input


@dataclass
class Sample:
    text: str
    label: str
    source: str = "user"
    category: str = "benign"
    note: str = ""


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

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
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 3), "recall": round(self.recall, 3),
            "f1": round(self.f1, 3), "accuracy": round(self.accuracy, 3),
        }


@dataclass
class EvalReport:
    threshold: float
    overall: Metrics
    per_category_recall: dict[str, float]
    false_positives: list[dict] = field(default_factory=list)
    false_negatives: list[dict] = field(default_factory=list)
    sweep: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "threshold": self.threshold,
            "overall": self.overall.to_dict(),
            "per_category_recall": self.per_category_recall,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "threshold_sweep": self.sweep,
        }


def load_dataset(path: str | Path) -> list[Sample]:
    samples = []
    for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{lineno}: invalid JSON ({exc})") from exc
        if obj.get("label") not in ("malicious", "benign"):
            raise ValueError(f"{path}:{lineno}: label must be 'malicious' or 'benign'")
        samples.append(Sample(
            text=obj["text"], label=obj["label"], source=obj.get("source", "user"),
            category=obj.get("category", "benign" if obj["label"] == "benign" else "uncategorized"),
            note=obj.get("note", ""),
        ))
    return samples


def _metrics_at(scored: list[tuple[Sample, float]], threshold: float) -> Metrics:
    m = Metrics()
    for sample, score in scored:
        predicted = score >= threshold
        actual = sample.label == "malicious"
        if predicted and actual:
            m.tp += 1
        elif predicted and not actual:
            m.fp += 1
        elif actual:
            m.fn += 1
        else:
            m.tn += 1
    return m


def evaluate(samples: list[Sample], threshold: float = DEFAULT_REVIEW_THRESHOLD) -> EvalReport:
    """Score every sample once; a sample is 'flagged' if risk >= threshold.

    The default threshold is the *review* threshold: anything the scanner
    would at least send for review counts as a detection.
    """
    scored = [(s, scan_input(s.text, s.source).risk_score) for s in samples]
    overall = _metrics_at(scored, threshold)

    cats: dict[str, list[bool]] = {}
    fps, fns = [], []
    for sample, score in scored:
        flagged = score >= threshold
        if sample.label == "malicious":
            cats.setdefault(sample.category, []).append(flagged)
            if not flagged:
                fns.append({"text": sample.text[:160], "category": sample.category, "score": score})
        elif flagged:
            fps.append({"text": sample.text[:160], "source": sample.source, "score": score})

    per_cat = {c: round(sum(v) / len(v), 3) for c, v in sorted(cats.items())}
    sweep_points = sorted({0.2, 0.3, threshold, 0.5, 0.6, DEFAULT_BLOCK_THRESHOLD, 0.8, 0.9})
    sweep = [{"threshold": t, **_metrics_at(scored, t).to_dict()} for t in sweep_points]

    return EvalReport(threshold, overall, per_cat, fps, fns, sweep)


def format_report(report: EvalReport) -> str:
    o = report.overall
    lines = [
        f"Evaluation @ threshold {report.threshold}",
        f"  precision {o.precision:.3f}   recall {o.recall:.3f}   F1 {o.f1:.3f}   accuracy {o.accuracy:.3f}",
        "",
        "  Confusion matrix        predicted+   predicted-",
        f"    actual malicious      {o.tp:>9}   {o.fn:>10}",
        f"    actual benign         {o.fp:>9}   {o.tn:>10}",
        "",
        "  Recall by attack category:",
    ]
    for cat, rec in report.per_category_recall.items():
        lines.append(f"    {cat:<24} {rec:.2f}")
    lines += ["", "  Threshold sweep:", "    thresh  precision  recall    F1"]
    for row in report.sweep:
        lines.append(f"    {row['threshold']:<6}  {row['precision']:<9}  {row['recall']:<8}  {row['f1']}")
    if report.false_negatives:
        lines += ["", f"  False negatives ({len(report.false_negatives)}):"]
        lines += [f"    [{fn['category']}] score={fn['score']} :: {fn['text']!r}" for fn in report.false_negatives]
    if report.false_positives:
        lines += ["", f"  False positives ({len(report.false_positives)}):"]
        lines += [f"    [{fp['source']}] score={fp['score']} :: {fp['text']!r}" for fp in report.false_positives]
    return "\n".join(lines)
