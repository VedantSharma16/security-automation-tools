"""Evaluation harness: measure detection quality on a labelled dataset.

A detection rule set without a measured false-positive rate is a liability
in production. This module scores the guardrail on data/eval_dataset.jsonl
(or any JSONL with the same schema) and reports precision / recall / F1,
false-positive rate, per-technique recall, and the exact misses.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Action
from .guard import Guardrail

DEFAULT_DATASET = Path(__file__).resolve().parent.parent / "data" / "eval_dataset.jsonl"


@dataclass
class EvalReport:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    blocked_attacks: int = 0
    by_technique: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))
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
    def false_positive_rate(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    def to_dict(self) -> dict:
        return {
            "confusion": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "attacks_blocked_outright": self.blocked_attacks,
            "recall_by_technique": {t: f"{hit}/{total}" for t, (hit, total) in sorted(self.by_technique.items())},
            "misses": self.misses,
            "false_positives": self.false_positives,
        }


def load_dataset(path: str | Path = DEFAULT_DATASET) -> list[dict]:
    with Path(path).open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def evaluate(samples: list[dict], guard: Guardrail | None = None) -> EvalReport:
    guard = guard or Guardrail()
    report = EvalReport()
    for sample in samples:
        verdict = guard.scan(sample["text"], sample.get("context", "input"))
        detected = verdict.action is not Action.ALLOW
        summary = {"id": sample["id"], "technique": sample.get("technique", ""),
                   "risk": verdict.risk_score, "action": verdict.action.value,
                   "rules": [f.rule_id for f in verdict.findings]}
        if sample["label"] == "injection":
            stats = report.by_technique[sample.get("technique", "unknown")]
            stats[1] += 1
            if detected:
                report.tp += 1
                stats[0] += 1
                report.blocked_attacks += verdict.action is Action.BLOCK
            else:
                report.fn += 1
                report.misses.append(summary)
        else:
            if detected:
                report.fp += 1
                report.false_positives.append(summary)
            else:
                report.tn += 1
    return report


def format_report(report: EvalReport) -> str:
    d = report.to_dict()
    c = d["confusion"]
    lines = [
        "Detection evaluation",
        "====================",
        f"  precision {d['precision']:.3f}   recall {d['recall']:.3f}   F1 {d['f1']:.3f}   "
        f"FPR {d['false_positive_rate']:.3f}",
        f"  TP {c['tp']}  FP {c['fp']}  TN {c['tn']}  FN {c['fn']}   "
        f"(attacks blocked outright: {d['attacks_blocked_outright']}/{c['tp'] + c['fn']})",
        "",
        "Recall by technique:",
    ]
    lines += [f"  {t:<22} {v}" for t, v in d["recall_by_technique"].items()]
    if report.misses:
        lines += ["", "Missed attacks (known gaps):"]
        lines += [f"  {m['id']} [{m['technique']}] risk={m['risk']}" for m in report.misses]
    if report.false_positives:
        lines += ["", "False positives:"]
        lines += [f"  {m['id']} risk={m['risk']} rules={m['rules']}" for m in report.false_positives]
    return "\n".join(lines)
