"""sigmalite: a small detection-as-code engine with Sigma-style rules."""

from .engine import Alert, Engine
from .rules import Rule, RuleError, load_rules

__all__ = ["Alert", "Engine", "Rule", "RuleError", "load_rules"]
__version__ = "0.1.0"
