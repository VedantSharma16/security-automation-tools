"""Evaluate detector quality on a labelled JSONL corpus (precision / recall / FPR)."""
from __future__ import annotations

import json
from pathlib import Path

from .scanner import scan


def evaluate(path: str | Path) -> dict:
    tp = fp = tn = fn = 0
    misses: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        flagged = scan(row["text"], row.get("source", "user")).verdict != "allow"
        malicious = row["label"] == "malicious"
        if malicious and flagged: tp += 1
        elif malicious: fn += 1; misses.append(row["text"][:80])
        elif flagged: fp += 1; misses.append("FP: " + row["text"][:80])
        else: tn += 1
    div = lambda a, b: round(a / b, 3) if b else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": div(tp, tp + fp), "recall": div(tp, tp + fn),
            "false_positive_rate": div(fp, fp + tn), "errors": misses}
