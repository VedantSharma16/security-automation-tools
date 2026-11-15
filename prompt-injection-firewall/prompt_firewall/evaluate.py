"""Evaluation harness: measure the firewall like a detection engineer would.

Reports precision / recall / F1 / false-positive rate for three
configurations (rules only, ML only, fused) so the contribution of each
layer is visible, plus per-category and per-evasion-technique recall so
blind spots are explicit rather than hidden inside one headline number.

The evaluation set (``data/eval.jsonl``) is disjoint from the training set.
Rows marked ``"mutate": true`` are additionally expanded through every
red-team mutator, so the benchmark covers obfuscated attacks.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .classifier import load_jsonl, train_default
from .firewall import Firewall
from .redteam import MUTATORS, mutate

DEFAULT_EVAL_PATH = Path(__file__).resolve().parent.parent / "data" / "eval.jsonl"


@dataclass
class Sample:
    text: str
    label: int
    category: str
    source: str
    technique: str = "plain"


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    per_category: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))
    per_technique: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))
    false_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)
    mean_latency_ms: float = 0.0

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
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    def summary(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 3), "recall": round(self.recall, 3),
            "f1": round(self.f1, 3), "false_positive_rate": round(self.fpr, 3),
            "mean_latency_ms": round(self.mean_latency_ms, 3),
            "recall_by_category": {k: f"{v[0]}/{v[1]}" for k, v in sorted(self.per_category.items())},
            "recall_by_technique": {k: f"{v[0]}/{v[1]}" for k, v in sorted(self.per_technique.items())},
        }


def load_samples(path: str | Path = DEFAULT_EVAL_PATH, with_mutations: bool = True) -> list[Sample]:
    samples: list[Sample] = []
    for row in load_jsonl(path):
        base = Sample(row["text"], int(row["label"]), row["category"], row.get("source", "user"))
        samples.append(base)
        if with_mutations and row.get("mutate") and base.label == 1:
            for i, technique in enumerate(sorted(MUTATORS)):
                samples.append(Sample(mutate(base.text, technique, seed=i), 1, base.category, base.source, technique))
    return samples


def evaluate(firewall: Firewall, samples: list[Sample]) -> Metrics:
    m = Metrics()
    started = time.perf_counter()
    for s in samples:
        detected = firewall.scan_input(s.text, source=s.source).action != "allow"  # type: ignore[arg-type]
        if s.label == 1:
            m.per_category[s.category][1] += 1
            m.per_technique[s.technique][1] += 1
            if detected:
                m.tp += 1
                m.per_category[s.category][0] += 1
                m.per_technique[s.technique][0] += 1
            else:
                m.fn += 1
                m.false_negatives.append(f"[{s.technique}] {s.text[:90]}")
        elif detected:
            m.fp += 1
            m.false_positives.append(s.text[:90])
        else:
            m.tn += 1
    m.mean_latency_ms = (time.perf_counter() - started) * 1000 / max(1, len(samples))
    return m


def run_ablation(path: str | Path = DEFAULT_EVAL_PATH, with_mutations: bool = True) -> dict[str, Metrics]:
    samples = load_samples(path, with_mutations)
    model = train_default()
    configs = {
        "rules_only": Firewall(model=None, use_ml=False),
        "ml_only": Firewall(model=model, use_rules=False),
        "fused": Firewall(model=model),
    }
    return {name: evaluate(fw, samples) for name, fw in configs.items()}


def format_report(results: dict[str, Metrics]) -> str:
    lines = [
        f"{'config':<12} {'prec':>6} {'recall':>7} {'f1':>6} {'fpr':>6} {'tp':>4} {'fp':>4} {'fn':>4} {'ms/sample':>10}",
        "-" * 66,
    ]
    for name, m in results.items():
        lines.append(
            f"{name:<12} {m.precision:>6.3f} {m.recall:>7.3f} {m.f1:>6.3f} {m.fpr:>6.3f} "
            f"{m.tp:>4} {m.fp:>4} {m.fn:>4} {m.mean_latency_ms:>10.3f}"
        )
    fused = results.get("fused")
    if fused:
        lines += ["", "Fused recall by attack category:"]
        lines += [f"  {k:<22} {v[0]:>3}/{v[1]:<3}" for k, v in sorted(fused.per_category.items())]
        lines += ["", "Fused recall by evasion technique:"]
        lines += [f"  {k:<22} {v[0]:>3}/{v[1]:<3}" for k, v in sorted(fused.per_technique.items())]
        if fused.false_negatives:
            lines += ["", "Missed attacks (fused):"] + [f"  - {t}" for t in fused.false_negatives]
        if fused.false_positives:
            lines += ["", "False positives (fused):"] + [f"  - {t}" for t in fused.false_positives]
    return "\n".join(lines)
