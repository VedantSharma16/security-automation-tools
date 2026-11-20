"""Sigma-compatible detection engine with detection-as-code testing."""

from .condition import ConditionError, parse_condition
from .engine import Alert, ScanResult, read_events, scan
from .matcher import MatcherError, compile_detection_item
from .rule import LintIssue, Rule, RuleError, compile_rule, lint_rule, lint_rules, load_rule, load_rules
from .testing import TestReport, run_rule_tests

__version__ = "0.1.0"
__all__ = [
    "Alert", "ConditionError", "LintIssue", "MatcherError", "Rule", "RuleError", "ScanResult",
    "TestReport", "compile_detection_item", "compile_rule", "lint_rule", "lint_rules", "load_rule",
    "load_rules", "parse_condition", "read_events", "run_rule_tests", "scan",
]
