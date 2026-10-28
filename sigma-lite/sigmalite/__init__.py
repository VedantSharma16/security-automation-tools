"""sigmalite: a small Sigma-compatible detection engine."""

from .engine import Alert, Engine
from .rules import Rule, RuleError, load_rules

__all__ = ["Alert", "Engine", "Rule", "RuleError", "load_rules"]
__version__ = "0.1.0"
