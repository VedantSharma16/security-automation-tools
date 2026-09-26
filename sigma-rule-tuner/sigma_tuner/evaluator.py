"""Evaluate a Sigma-style rule against labeled sample telemetry."""

from __future__ import annotations

import json
from pathlib import Path

from sigma_tuner.dsl import evaluate_rule


def load_events(path: str | Path) -> list[dict]:
    """Load newline-delimited JSON events. Each event must include a boolean "label" field."""
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def evaluate_metrics(rule: dict, events: list[dict]) -> dict:
    """Score `rule` against `events` (ground truth taken from each event's "label" field)."""
    tp = fp = fn = tn = 0
    matched_indices: list[int] = []

    for i, event in enumerate(events):
        predicted = evaluate_rule(rule, event)
        actual = bool(event.get("label", False))
        if predicted:
            matched_indices.append(i)
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "total_events": len(events),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "matched_indices": matched_indices,
    }
