"""Evaluate detector quality against a labelled JSONL corpus."""

from __future__ import annotations

import json
from pathlib import Path

from .scanner import scan


def evaluate(corpus: Path, flag: str = "review") -> dict:
    """Label 'malicious' counts as detected when verdict is review/block (flag=review) or block."""
    flagged = {"block"} if flag == "block" else {"review", "block"}
    tp = fp = tn = fn = 0
    misses, false_alarms = [], []
    for line in corpus.read_text().splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        hit = scan(item["text"]).verdict in flagged
        if item["label"] == "malicious":
            tp, fn = (tp + 1, fn) if hit else (tp, fn + 1)
            if not hit:
                misses.append(item["text"][:80])
        else:
            fp, tn = (fp + 1, tn) if hit else (fp, tn + 1)
            if hit:
                false_alarms.append(item["text"][:80])
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": round(prec, 3),
            "recall": round(rec, 3), "misses": misses, "false_alarms": false_alarms}
