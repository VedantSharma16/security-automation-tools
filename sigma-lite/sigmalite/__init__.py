"""sigmalite: a small Sigma-compatible detection engine."""

from .engine import Match, evaluate_events
from .rule import Rule, RuleError, load_rule, load_rules

__all__ = ["Match", "Rule", "RuleError", "evaluate_events", "load_rule", "load_rules"]
