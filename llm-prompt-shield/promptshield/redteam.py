"""Red-team harness: run a labelled corpus through the scanner and report metrics."""
from __future__ import annotations

import json
from collections import defaultdict
from importlib import resources
from pathlib import Path

from .scanner import scan


def load_corpus(path: str | Path | None = None) -> list[dict]:
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    return json.loads(resources.files("promptshield").joinpath("data/corpus.json").read_text(encoding="utf-8"))


def evaluate(corpus: list[dict]) -> dict:
    """Each sample: {text, direction, malicious(bool), category}. 'Detected' == verdict != allow."""
    tp = fp = tn = fn = 0
    per_cat: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "detected": 0})
    misses, false_alarms = [], []
    for s in corpus:
        res = scan(s["text"], s.get("direction", "input"))
        flagged = res.verdict != "allow"
        if s["malicious"]:
            per_cat[s["category"]]["total"] += 1
            if flagged:
                tp += 1
                per_cat[s["category"]]["detected"] += 1
            else:
                fn += 1
                misses.append(s["text"][:80])
        else:
            if flagged:
                fp += 1
                false_alarms.append(s["text"][:80])
            else:
                tn += 1
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "samples": len(corpus), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "per_category": {k: {**v, "recall": round(v["detected"] / v["total"], 3)} for k, v in sorted(per_cat.items())},
        "missed": misses, "false_alarms": false_alarms,
    }
