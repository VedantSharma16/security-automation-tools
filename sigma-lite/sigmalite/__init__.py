"""sigmalite: a lightweight Sigma-style detection engine."""

from .engine import Match, scan_events
from .rule import Rule, RuleError, load_rules

__all__ = ["Match", "Rule", "RuleError", "load_rules", "scan_events"]
