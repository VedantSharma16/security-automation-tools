"""sigmalite: a lightweight Sigma-compatible detection rule engine."""

from .engine import Match, evaluate, scan
from .rules import Rule, RuleError, load_rule, load_rules

__all__ = ["Match", "Rule", "RuleError", "evaluate", "load_rule", "load_rules", "scan"]
