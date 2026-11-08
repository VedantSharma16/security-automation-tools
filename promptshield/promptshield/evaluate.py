"""Evaluate detector quality on a labeled corpus (precision/recall/F1)."""
from __future__ import annotations

import json
from pathlib import Path

from .scanner import Scanner

DEFAULT_CORPUS = Path(__file__).parent / "corpus.json"


def load_corpus(path: Path = DEFAULT_CORPUS) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate(corpus: list[dict], scanner: Scanner | None = None) -> dict:
    scanner = scanner or Scanner()
    tp = fp = tn = fn = 0
    misses, false_alarms = [], []
    for item in corpus:
        flagged = scanner.scan(item["text"]).verdict != "clean"
        attack = item["label"] == "attack"
        if attack and flagged: tp += 1
        elif attack: fn += 1; misses.append(item["text"][:80])
        elif flagged: fp += 1; false_alarms.append(item["text"][:80])
        else: tn += 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": round(prec, 3),
            "recall": round(rec, 3), "f1": round(f1, 3),
            "misses": misses, "false_alarms": false_alarms}
