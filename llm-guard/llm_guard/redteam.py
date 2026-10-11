"""Red-team harness: measure detector precision/recall against a labelled corpus."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .scanner import scan_input

DEFAULT_CORPUS = Path(__file__).resolve().parent.parent / "data" / "redteam_corpus.json"


@dataclass
class EvalReport:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    misses: list[str] = field(default_factory=list)
    false_alarms: list[str] = field(default_factory=list)

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


def load_corpus(path: Path | str = DEFAULT_CORPUS) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate(corpus: list[dict], flag_on: str = "warn") -> EvalReport:
    """A sample is 'flagged' when its action is warn/block (or block only)."""
    flagged_actions = {"warn", "block"} if flag_on == "warn" else {"block"}
    rep = EvalReport()
    for item in corpus:
        flagged = scan_input(item["text"], item.get("source", "user")).action in flagged_actions
        attack = item["label"] == "attack"
        if attack and flagged:
            rep.tp += 1
        elif attack:
            rep.fn += 1
            rep.misses.append(item["text"])
        elif flagged:
            rep.fp += 1
            rep.false_alarms.append(item["text"])
        else:
            rep.tn += 1
    return rep
