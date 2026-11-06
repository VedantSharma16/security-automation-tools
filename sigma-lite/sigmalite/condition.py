"""Parser/evaluator for Sigma condition expressions.

Grammar (lowest to highest precedence): ``or`` < ``and`` < ``not`` < atom, where
atom is ``name``, ``(expr)``, ``1 of pattern``, ``all of pattern`` or ``... of them``.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Callable

from .matcher import RuleError

_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


def _tokenize(text: str) -> list[str]:
    pos, tokens = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise RuleError(f"cannot tokenize condition at {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


@dataclass
class Condition:
    """A compiled condition: call ``evaluate`` with {selection_name: bool}."""
    text: str
    _fn: Callable[[dict[str, bool]], bool]
    references: frozenset[str]

    def evaluate(self, results: dict[str, bool]) -> bool:
        return self._fn(results)


class _Parser:
    def __init__(self, tokens: list[str], names: list[str]):
        self.t, self.i, self.names = tokens, 0, names
        self.refs: set[str] = set()

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def next(self) -> str:
        tok = self.peek()
        if tok is None:
            raise RuleError("unexpected end of condition")
        self.i += 1
        return tok

    def parse(self):
        node = self.or_()
        if self.peek() is not None:
            raise RuleError(f"unexpected token {self.peek()!r} in condition")
        return node

    def or_(self):
        left = self.and_()
        while (self.peek() or "").lower() == "or":
            self.next()
            right = self.and_()
            left = (lambda a, b: lambda r: a(r) or b(r))(left, right)
        return left

    def and_(self):
        left = self.not_()
        while (self.peek() or "").lower() == "and":
            self.next()
            right = self.not_()
            left = (lambda a, b: lambda r: a(r) and b(r))(left, right)
        return left

    def not_(self):
        if (self.peek() or "").lower() == "not":
            self.next()
            inner = self.not_()
            return lambda r: not inner(r)
        return self.atom()

    def atom(self):
        tok = self.next()
        if tok == "(":
            node = self.or_()
            if self.next() != ")":
                raise RuleError("missing closing parenthesis")
            return node
        if tok == ")":
            raise RuleError("unbalanced parenthesis")
        if tok.lower() in ("all", "1") and (self.peek() or "").lower() == "of":
            self.next()
            pattern = self.next()
            matched = self.names if pattern == "them" else fnmatch.filter(self.names, pattern)
            if not matched:
                raise RuleError(f"pattern {pattern!r} matches no selection")
            self.refs.update(matched)
            agg = all if tok.lower() == "all" else any
            return lambda r, m=tuple(matched), agg=agg: agg(r[n] for n in m)
        if tok not in self.names:
            raise RuleError(f"condition references undefined selection {tok!r}")
        self.refs.add(tok)
        return lambda r, n=tok: r[n]


def compile_condition(text: str, selection_names: list[str]) -> Condition:
    tokens = _tokenize(text)
    if not tokens:
        raise RuleError("empty condition")
    p = _Parser(tokens, selection_names)
    fn = p.parse()
    return Condition(text, fn, frozenset(p.refs))
