"""sigmalite: a small Sigma-inspired detection-as-code engine."""

from .engine import Match, scan
from .rules import Rule, RuleError, load_rules

__all__ = ["Match", "Rule", "RuleError", "load_rules", "scan"]
__version__ = "0.1.0"
