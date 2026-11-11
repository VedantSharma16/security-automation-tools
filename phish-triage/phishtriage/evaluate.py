"""Measure detection quality against a labeled corpus of .eml files.

The corpus directory must contain a ``labels.json`` mapping file names to
``"phish"`` or ``"benign"``. An email counts as a positive prediction when
its verdict is ``suspicious`` or ``malicious`` (i.e. it would be escalated to
an analyst). Reporting precision/recall rather than raw accuracy matters
here: a triage tool that misses phish (low recall) is dangerous, and one
that escalates everything (low precision) burns analyst time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .analyzer import analyze_file

POSITIVE_VERDICTS = {"suspicious", "malicious"}


@dataclass
class EvalResult:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    rows: list[dict] = field(default_factory=list)

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

    def to_dict(self) -> dict:
        return {
            "confusion_matrix": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "samples": self.rows,
        }


def evaluate(corpus: str | Path) -> EvalResult:
    corpus = Path(corpus)
    labels: dict[str, str] = json.loads((corpus / "labels.json").read_text("utf-8"))
    result = EvalResult()
    for name, label in sorted(labels.items()):
        if label not in ("phish", "benign"):
            raise ValueError(f"{name}: label must be 'phish' or 'benign', got {label!r}")
        report = analyze_file(corpus / name)
        verdict = report["summary"]["verdict"]
        predicted = verdict in POSITIVE_VERDICTS
        actual = label == "phish"
        outcome = {(True, True): "tp", (True, False): "fp",
                   (False, False): "tn", (False, True): "fn"}[(predicted, actual)]
        setattr(result, outcome, getattr(result, outcome) + 1)
        result.rows.append({"file": name, "label": label, "verdict": verdict,
                            "risk_score": report["summary"]["risk_score"], "outcome": outcome.upper()})
    return result


def format_eval(result: EvalResult) -> str:
    lines = [f"{'file':<34} {'label':<7} {'verdict':<11} {'score':>5}  outcome", "-" * 70]
    for r in result.rows:
        lines.append(f"{r['file']:<34} {r['label']:<7} {r['verdict']:<11} {r['risk_score']:>5}  {r['outcome']}")
    lines += [
        "-" * 70,
        f"TP={result.tp} FP={result.fp} TN={result.tn} FN={result.fn}",
        f"precision={result.precision:.3f} recall={result.recall:.3f} f1={result.f1:.3f}",
    ]
    return "\n".join(lines)
