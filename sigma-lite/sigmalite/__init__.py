"""sigma-lite: a small Sigma-style detection engine."""
from .engine import Engine, Match
from .rule import Rule, RuleError, load_rules

__all__ = ["Engine", "Match", "Rule", "RuleError", "load_rules"]
