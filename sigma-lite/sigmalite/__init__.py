"""sigma-lite: a small Sigma-compatible detection engine."""
from .condition import ConditionError, parse_condition
from .engine import Match, evaluate_events
from .rules import Rule, RuleError, load_rules

__all__ = ["ConditionError", "Match", "Rule", "RuleError", "evaluate_events",
           "load_rules", "parse_condition"]
__version__ = "0.1.0"
