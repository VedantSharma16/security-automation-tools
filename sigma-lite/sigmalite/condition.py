"""Parser/evaluator for Sigma condition expressions.

Grammar:  or_expr  := and_expr ('or' and_expr)*
          and_expr := not_expr ('and' not_expr)*
          not_expr := 'not' not_expr | atom
          atom     := '(' or_expr ')' | ('1'|'all') 'of' (name|pattern|'them') | name
"""
from __future__ import annotations

import fnmatch
import re
from typing import Callable

Evaluator = Callable[[dict[str, bool]], bool]
_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")
_KEYWORDS = {"and", "or", "not", "of"}


class ConditionError(ValueError):
    pass


def _tokenize(text: str) -> list[str]:
    pos, toks = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"cannot tokenize at {text[pos:]!r}")
        toks.append(m.group(1))
        pos = m.end()
    return toks


def parse_condition(text: str, selection_names: set[str]) -> Evaluator:
    """Compile *text* to a function of {selection name: matched?}."""
    toks = _tokenize(text)
    if not toks:
        raise ConditionError("empty condition")
    i = 0

    def peek() -> str | None:
        return toks[i] if i < len(toks) else None

    def take() -> str:
        nonlocal i
        if i >= len(toks):
            raise ConditionError("unexpected end of condition")
        i += 1
        return toks[i - 1]

    def or_expr() -> Evaluator:
        parts = [and_expr()]
        while peek() and peek().lower() == "or":
            take()
            parts.append(and_expr())
        return parts[0] if len(parts) == 1 else (lambda r: any(p(r) for p in parts))

    def and_expr() -> Evaluator:
        parts = [not_expr()]
        while peek() and peek().lower() == "and":
            take()
            parts.append(not_expr())
        return parts[0] if len(parts) == 1 else (lambda r: all(p(r) for p in parts))

    def not_expr() -> Evaluator:
        if peek() and peek().lower() == "not":
            take()
            inner = not_expr()
            return lambda r: not inner(r)
        return atom()

    def atom() -> Evaluator:
        tok = take()
        if tok == "(":
            inner = or_expr()
            if take() != ")":
                raise ConditionError("expected ')'")
            return inner
        if tok == ")" or tok.lower() in _KEYWORDS:
            raise ConditionError(f"unexpected token {tok!r}")
        if peek() and peek().lower() == "of":
            if tok.lower() not in ("1", "all", "any"):
                raise ConditionError(f"quantifier must be 1 or all, got {tok!r}")
            take()
            target = take()
            names = (sorted(selection_names) if target.lower() == "them"
                     else sorted(fnmatch.filter(selection_names, target)))
            if not names:
                raise ConditionError(f"'{target}' matches no selections")
            agg = all if tok.lower() == "all" else any
            return lambda r: agg(r[n] for n in names)
        if tok not in selection_names:
            raise ConditionError(f"unknown selection {tok!r}")
        return lambda r: r[tok]

    expr = or_expr()
    if i != len(toks):
        raise ConditionError(f"trailing tokens: {toks[i:]}")
    return expr
