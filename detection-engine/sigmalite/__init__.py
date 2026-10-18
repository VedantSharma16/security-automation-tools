"""sigmalite: a small Sigma-style detection engine."""
from .rules import Rule, RuleError, load_rules, load_rule_file
from .engine import Alert, scan_events

__all__ = ["Rule", "RuleError", "load_rules", "load_rule_file", "Alert", "scan_events"]
