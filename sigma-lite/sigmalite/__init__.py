"""sigma-lite: a lightweight Sigma-compatible detection engine."""
from .engine import Engine, Match
from .rule import Rule, RuleError, load_rules

__all__ = ["Engine", "Match", "Rule", "RuleError", "load_rules"]
__version__ = "0.1.0"
