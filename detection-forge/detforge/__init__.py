"""detection-forge: a Sigma-inspired detection-as-code engine."""
from .engine import Rule, RuleError, load_rules, load_rule_file
from .condition import ConditionError

__all__ = ["Rule", "RuleError", "ConditionError", "load_rules", "load_rule_file"]
__version__ = "0.1.0"
