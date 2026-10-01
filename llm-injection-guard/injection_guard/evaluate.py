"""Evaluation harness: measure detection quality on a labeled JSONL corpus."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from injection_guard.scanner import scan

DEFAULT_CORPUS = Path(__file__).resolve().parent.parent / "data" / "eval_corpus.jsonl"


@dataclass
class EvalReport:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    misses: list[dict] = field(default_factory=list)
    false_alarms: list[dict] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def to_dict(self) -> dict:
        return {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
                "precision": round(self.precision, 3), "recall": round(self.recall, 3),
                "f1": round(self.f1, 3), "misses": self.misses, "false_alarms": self.false_alarms}


def load_corpus(path: Path | str = DEFAULT_CORPUS) -> list[dict]:
    rows = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("label") not in ("malicious", "benign") or "text" not in row:
            raise ValueError(f"line {n}: needs 'text' and label malicious|benign")
        rows.append(row)
    return rows


def evaluate(rows: list[dict], flag_counts_as_detection: bool = True) -> EvalReport:
    rep = EvalReport()
    for row in rows:
        res = scan(row["text"], row.get("source", "user"))
        detected = res.verdict != "allow" if flag_counts_as_detection else res.verdict == "block"
        bad = row["label"] == "malicious"
        if bad and detected:
            rep.tp += 1
        elif bad:
            rep.fn += 1
            rep.misses.append({"text": row["text"], "score": res.score})
        elif detected:
            rep.fp += 1
            rep.false_alarms.append({"text": row["text"], "score": res.score})
        else:
            rep.tn += 1
    return rep
