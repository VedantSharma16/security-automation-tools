"""A small, dependency-free evaluator for a Sigma-rule subset.

Real Sigma (https://github.com/SigmaHQ/sigma-specification) rules separate
*what pattern to look for* (the ``detection`` block) from *how blocks combine*
(the ``condition`` string), and get compiled to a specific backend (Splunk,
Elastic, etc.) at deploy time. This module implements just enough of that
model to evaluate a rule directly against a stream of structured event dicts
in Python -- there is no backend, no aggregation (``count() by`` timeframes),
and no full Sigma modifier set. What's implemented:

* Field modifiers: plain equality, ``contains``, ``startswith``, ``endswith``,
  ``re`` (regex search), and ``gte``/``lte``/``gt``/``lt`` (numeric compares --
  a deliberate extension beyond the spec, since evaluating pre-aggregated
  fields like ``failed_attempts_5m`` per-event is a common pattern once a SIEM
  has already computed a windowed count).
* A block (e.g. ``selection``, ``filter``) is an AND of its fields; a field
  given a list of values is an OR across that list.
* The ``condition`` string combines block names with ``and`` / ``or`` /
  ``not`` / parentheses.

The condition string is evaluated with Python's ``ast`` module restricted to
boolean-logic nodes only -- never with ``eval()`` -- so a malformed or
adversarial condition string can raise but can never execute arbitrary code.
"""

from __future__ import annotations

import ast
import re as _re
from typing import Any

_STRING_MODIFIERS = ("contains", "startswith", "endswith")
_NUMERIC_MODIFIERS = ("gte", "lte", "gt", "lt")


class ConditionError(ValueError):
    """Raised when a Sigma ``condition`` string can't be safely evaluated."""


def _values_eq(value: Any, candidate: Any) -> bool:
    if isinstance(value, str) and isinstance(candidate, str):
        return value.lower() == candidate.lower()
    return value == candidate


def _string_op(modifier: str, value: str, candidate: str) -> bool:
    value_l, candidate_l = value.lower(), candidate.lower()
    if modifier == "contains":
        return candidate_l in value_l
    if modifier == "startswith":
        return value_l.startswith(candidate_l)
    return value_l.endswith(candidate_l)  # endswith


def evaluate_field(event: dict, field_spec: str, expected: Any) -> bool:
    """Evaluate one ``field`` or ``field|modifier`` spec against an event."""
    field, sep, modifier = field_spec.partition("|")
    if field not in event or event[field] is None:
        return False
    value = event[field]
    candidates = expected if isinstance(expected, list) else [expected]

    if not sep:  # plain equality (or membership, for a list of candidates)
        return any(_values_eq(value, c) for c in candidates)

    if modifier in _STRING_MODIFIERS:
        if not isinstance(value, str):
            return False
        return any(isinstance(c, str) and _string_op(modifier, value, c) for c in candidates)

    if modifier == "re":
        if not isinstance(value, str):
            return False
        return any(_re.search(c, value) is not None for c in candidates)

    if modifier in _NUMERIC_MODIFIERS:
        try:
            numeric_value = float(value)
        except (TypeError, ValueError):
            return False
        for c in candidates:
            try:
                numeric_candidate = float(c)
            except (TypeError, ValueError):
                continue
            if modifier == "gte" and numeric_value >= numeric_candidate:
                return True
            if modifier == "lte" and numeric_value <= numeric_candidate:
                return True
            if modifier == "gt" and numeric_value > numeric_candidate:
                return True
            if modifier == "lt" and numeric_value < numeric_candidate:
                return True
        return False

    raise ValueError(f"unknown field modifier {modifier!r} in {field_spec!r}")


def evaluate_block(event: dict, block: dict) -> bool:
    """A block matches when ALL of its field specs match (logical AND)."""
    return all(evaluate_field(event, field_spec, expected) for field_spec, expected in block.items())


_ALLOWED_NODES = (
    ast.Expression,
    ast.BoolOp,
    ast.And,
    ast.Or,
    ast.UnaryOp,
    ast.Not,
    ast.Name,
    ast.Load,
)


def evaluate_condition(condition: str, block_results: dict[str, bool]) -> bool:
    """Safely evaluate a Sigma ``condition`` string against named block results.

    Supports block names combined with ``and``/``or``/``not`` and parens,
    e.g. ``"selection and not filter"``. Never calls ``eval()``: the
    condition is parsed to an AST and walked with an explicit node allowlist,
    so it cannot invoke functions, do attribute access, or run arbitrary code.
    """
    try:
        tree = ast.parse(condition, mode="eval")
    except SyntaxError as exc:
        raise ConditionError(f"invalid condition syntax: {condition!r}") from exc

    def _walk(node: ast.AST) -> bool:
        if not isinstance(node, _ALLOWED_NODES):
            raise ConditionError(f"disallowed expression in condition: {ast.dump(node)}")
        if isinstance(node, ast.Expression):
            return _walk(node.body)
        if isinstance(node, ast.BoolOp):
            values = [_walk(v) for v in node.values]
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if isinstance(node, ast.UnaryOp):
            return not _walk(node.operand)
        if isinstance(node, ast.Name):
            if node.id not in block_results:
                raise ConditionError(f"condition references unknown block {node.id!r}")
            return block_results[node.id]
        raise ConditionError(f"disallowed expression in condition: {ast.dump(node)}")  # pragma: no cover

    return _walk(tree)


def evaluate_rule(rule: dict, event: dict) -> bool:
    """Evaluate a full Sigma-style rule dict (with a ``detection`` block) against one event."""
    detection = rule["detection"]
    condition = detection["condition"]
    block_results = {name: evaluate_block(event, block) for name, block in detection.items() if name != "condition"}
    return evaluate_condition(condition, block_results)
