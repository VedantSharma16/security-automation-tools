"""sigma-rule-tuner: automated Sigma detection rule tuning against labeled telemetry."""

from sigma_tuner.dsl import evaluate_rule
from sigma_tuner.evaluator import evaluate_metrics, load_events
from sigma_tuner.rule_builder import build_rule
from sigma_tuner.technique_kb import get_technique, list_techniques
from sigma_tuner.tuner import TuningResult, tune

__version__ = "0.1.0"

__all__ = [
    "evaluate_rule",
    "evaluate_metrics",
    "load_events",
    "build_rule",
    "get_technique",
    "list_techniques",
    "TuningResult",
    "tune",
]
