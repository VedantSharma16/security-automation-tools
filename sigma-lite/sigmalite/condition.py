"""Parser/evaluator for Sigma condition expressions.

Grammar (precedence low -> high):
    expr    := or_expr
    or_expr := and_expr ('or' and_expr)*
    and_expr:= not_expr ('and' not_expr)*
    not_expr:= 'not' not_expr | atom
    atom    := '(' expr ')' | quant | NAME
    quant   := ('1 of' | 'all of') (NAME_GLOB | 'them')
"""
from __future__ import annotations

import fnmatch
import re
from typing import Callable

_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


class ConditionError(ValueError):
    pass


def _tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"cannot tokenize condition at: {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], names: list[str]):
        self.t, self.i, self.names = tokens, 0, names

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        node = self.or_expr()
        if self.i != len(self.t):
            raise ConditionError(f"unexpected token {self.t[self.i]!r}")
        return node

    def or_expr(self):
        node = self.and_expr()
        while self.peek() == "or":
            self.take()
            node = ("or", node, self.and_expr())
        return node

    def and_expr(self):
        node = self.not_expr()
        while self.peek() == "and":
            self.take()
            node = ("and", node, self.not_expr())
        return node

    def not_expr(self):
        if self.peek() == "not":
            self.take()
            return ("not", self.not_expr())
        return self.atom()

    def atom(self):
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        if tok == "(":
            self.take()
            node = self.or_expr()
            if self.peek() != ")":
                raise ConditionError("missing closing parenthesis")
            self.take()
            return node
        if tok in ("1", "all"):
            quant = self.take().lower()
            if self.peek() != "of":
                raise ConditionError(f"expected 'of' after {quant!r}")
            self.take()
            if self.peek() is None:
                raise ConditionError("expected selection pattern after 'of'")
            pattern = self.take()
            matched = (
                list(self.names) if pattern.lower() == "them"
                else [n for n in self.names if fnmatch.fnmatchcase(n, pattern)]
            )
            if not matched:
                raise ConditionError(f"pattern {pattern!r} matches no selection")
            return ("any" if quant == "1" else "all", matched)
        if tok in (")", "and", "or", "of"):
            raise ConditionError(f"unexpected token {tok!r}")
        name = self.take()
        if name not in self.names:
            raise ConditionError(f"unknown selection {name!r}")
        return ("sel", name)


def compile_condition(text: str, names: list[str]) -> Callable[[dict[str, bool]], bool]:
    """Compile a condition into a function of {selection_name: matched}."""
    tree = _Parser(_tokenize(text), names).parse()

    def ev(node, r):
        kind = node[0]
        if kind == "sel":
            return r[node[1]]
        if kind == "not":
            return not ev(node[1], r)
        if kind == "and":
            return ev(node[1], r) and ev(node[2], r)
        if kind == "or":
            return ev(node[1], r) or ev(node[2], r)
        if kind == "any":
            return any(r[n] for n in node[1])
        return all(r[n] for n in node[1])

    return lambda results: ev(tree, results)
