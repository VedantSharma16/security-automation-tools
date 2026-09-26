"""The tuning loop: observe -> pick the next candidate variant -> re-evaluate -> stop or continue.

This is the same plan-act-observe shape as recon-agent's reconnaissance
loop, applied to detection engineering instead of recon: at each step the
loop "acts" by trying the technique KB's next rule variant, "observes" by
scoring it against labeled telemetry, and decides whether the result is good
enough to stop on. Unlike recon-agent there's no LLM in this decision --
precision/recall against ground truth is an objective signal, so the search
itself stays deterministic; an LLM is only ever used afterwards, in
`narrative.py`, to write up the *reasoning* behind the result.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sigma_tuner.evaluator import evaluate_metrics
from sigma_tuner.rule_builder import build_rule
from sigma_tuner.technique_kb import get_technique

DEFAULT_PRECISION_THRESHOLD = 0.8
DEFAULT_RECALL_THRESHOLD = 0.8


@dataclass
class TuningStep:
    variant_id: str
    rationale: str
    rule: dict
    metrics: dict


@dataclass
class TuningResult:
    technique_id: str
    steps: list[TuningStep] = field(default_factory=list)
    converged: bool = False
    best_index: int = 0

    @property
    def final_step(self) -> TuningStep:
        return self.steps[self.best_index]

    @property
    def final_rule(self) -> dict:
        return self.final_step.rule

    @property
    def final_metrics(self) -> dict:
        return self.final_step.metrics


def tune(
    technique_id: str,
    events: list[dict],
    *,
    precision_threshold: float = DEFAULT_PRECISION_THRESHOLD,
    recall_threshold: float = DEFAULT_RECALL_THRESHOLD,
    max_iterations: int | None = None,
) -> TuningResult:
    """Walk `technique_id`'s KB variants (broad -> narrow), scoring each against `events`.

    Stops as soon as a variant meets both thresholds. If none do within
    `max_iterations`, falls back to whichever variant had the best F1 score,
    so the caller always gets a usable rule plus an honest `converged` flag.
    """
    technique = get_technique(technique_id)
    variants = technique["variants"]
    if max_iterations is not None:
        variants = variants[:max_iterations]
    if not variants:
        raise ValueError(f"technique {technique_id!r} has no rule variants to try")

    result = TuningResult(technique_id=technique_id)
    best_f1 = -1.0

    for index, variant in enumerate(variants):
        rule = build_rule(technique, technique_id, variant)
        metrics = evaluate_metrics(rule, events)
        result.steps.append(
            TuningStep(variant_id=variant["id"], rationale=variant.get("rationale", ""), rule=rule, metrics=metrics)
        )

        if metrics["f1"] > best_f1:
            best_f1 = metrics["f1"]
            result.best_index = index

        if metrics["precision"] >= precision_threshold and metrics["recall"] >= recall_threshold:
            result.converged = True
            result.best_index = index
            break

    return result
