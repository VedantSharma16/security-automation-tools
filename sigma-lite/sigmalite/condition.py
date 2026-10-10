"""Parser/evaluator for Sigma condition expressions.

Grammar:  or_expr  := and_expr ('or' and_expr)*
          and_expr := not_expr ('and' not_expr)*
          not_expr := 'not' not_expr | atom
          atom     := '(' or_expr ')' | quant 'of' target | identifier
          quant    := '1' | 'all' ;  target := 'them' | glob*
"""
from __future__ import annotations

import fnmatch
import re
from typing import Callable

from .matcher import MatchError


class ConditionError(ValueError):
    pass


_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


def tokenize(text: str) -> list[str]:
    pos, tokens = 0, []
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            break
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


def parse(text: str, names: list[str]):
    """Return a callable(results: dict[str, bool]) -> bool, validating names."""
    tokens = tokenize(text)
    state = {"i": 0}

    def peek():
        return tokens[state["i"]] if state["i"] < len(tokens) else None

    def take():
        tok = peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        state["i"] += 1
        return tok

    def or_expr():
        parts = [and_expr()]
        while peek() and peek().lower() == "or":
            take()
            parts.append(and_expr())
        return lambda r: any(p(r) for p in parts)

    def and_expr():
        parts = [not_expr()]
        while peek() and peek().lower() == "and":
            take()
            parts.append(not_expr())
        return lambda r: all(p(r) for p in parts)

    def not_expr():
        if peek() and peek().lower() == "not":
            take()
            inner = not_expr()
            return lambda r: not inner(r)
        return atom()

    def atom():
        tok = take()
        if tok == "(":
            inner = or_expr()
            if take() != ")":
                raise ConditionError("expected ')'")
            return inner
        if tok == ")" or tok.lower() in ("and", "or", "not", "of"):
            raise ConditionError(f"unexpected token {tok!r}")
        if peek() and peek().lower() == "of":
            take()
            target = take()
            if tok.lower() not in ("1", "all"):
                raise ConditionError(f"unsupported quantifier {tok!r}")
            chosen = names if target.lower() == "them" else fnmatch.filter(names, target)
            if not chosen:
                raise ConditionError(f"'{tok} of {target}' matches no selections")
            agg: Callable = all if tok.lower() == "all" else any
            return lambda r: agg(r[n] for n in chosen)
        if tok not in names:
            raise ConditionError(f"condition references unknown selection {tok!r}")
        return lambda r: r[tok]

    fn = or_expr()
    if peek() is not None:
        raise ConditionError(f"unexpected token {peek()!r}")
    return fn
