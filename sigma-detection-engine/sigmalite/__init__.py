"""sigmalite: a small, dependency-light Sigma detection engine."""

from .rule import Rule, RuleError, load_rule, load_rules
from .engine import Alert, Engine

__all__ = ["Alert", "Engine", "Rule", "RuleError", "load_rule", "load_rules"]
__version__ = "0.1.0"
