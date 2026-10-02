"""Red-team harness: measures guard detection rate and false-positive rate."""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .scanner import Guard

DEFAULT_CORPUS = Path(__file__).resolve().parent.parent / "data" / "corpus.json"


@dataclass
class EvalReport:
    attacks_total: int = 0
    attacks_blocked: int = 0
    benign_total: int = 0
    benign_blocked: int = 0
    by_category: dict = field(default_factory=lambda: defaultdict(lambda: [0, 0]))
    missed: list = field(default_factory=list)
    false_positives: list = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        return self.attacks_blocked / self.attacks_total if self.attacks_total else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.benign_blocked / self.benign_total if self.benign_total else 0.0

    def to_dict(self) -> dict:
        return {
            "detection_rate": round(self.detection_rate, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "attacks": {"total": self.attacks_total, "blocked": self.attacks_blocked},
            "benign": {"total": self.benign_total, "blocked": self.benign_blocked},
            "by_category": {k: {"blocked": v[0], "total": v[1]} for k, v in sorted(self.by_category.items())},
            "missed": self.missed,
            "false_positives": self.false_positives,
        }

    def render(self) -> str:
        lines = [
            f"Detection rate:       {self.detection_rate:6.1%} ({self.attacks_blocked}/{self.attacks_total})",
            f"False-positive rate:  {self.false_positive_rate:6.1%} ({self.benign_blocked}/{self.benign_total})",
            "", "By attack category:",
        ]
        for cat, (hit, tot) in sorted(self.by_category.items()):
            lines.append(f"  {cat:<24} {hit}/{tot}")
        if self.missed:
            lines += ["", "Missed attacks:"] + [f"  - [{m['category']}] {m['prompt'][:70]!r}" for m in self.missed]
        if self.false_positives:
            lines += ["", "False positives:"] + [f"  - {p[:70]!r}" for p in self.false_positives]
        return "\n".join(lines)


def load_corpus(path: Path | str = DEFAULT_CORPUS) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate(guard: Guard, corpus: dict | None = None) -> EvalReport:
    corpus = corpus or load_corpus()
    rep = EvalReport()
    for item in corpus["attacks"]:
        blocked = guard.scan_input(item["prompt"]).blocked
        rep.attacks_total += 1
        rep.by_category[item["category"]][1] += 1
        if blocked:
            rep.attacks_blocked += 1
            rep.by_category[item["category"]][0] += 1
        else:
            rep.missed.append(item)
    for prompt in corpus["benign"]:
        rep.benign_total += 1
        if guard.scan_input(prompt).blocked:
            rep.benign_blocked += 1
            rep.false_positives.append(prompt)
    return rep
