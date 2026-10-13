"""Parser/evaluator for Sigma condition expressions.

Grammar (lowest to highest precedence)::

    expr   := term ("or" term)*
    term   := factor ("and" factor)*
    factor := "not" factor | "(" expr ")" | quantifier | NAME
    quantifier := ("1" | "all") "of" (NAME_GLOB | "them")
"""
from __future__ import annotations

import fnmatch
import re
from typing import Callable

_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


class ConditionError(ValueError):
    pass


def tokenize(text: str) -> list[str]:
    pos, tokens = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"cannot tokenize condition at {pos}: {text!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], names: list[str]):
        self.toks, self.i, self.names = tokens, 0, names

    def peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        self.i += 1
        return tok

    def parse(self):
        node = self.expr()
        if self.peek() is not None:
            raise ConditionError(f"unexpected token {self.peek()!r}")
        return node

    def expr(self):
        node = self.term()
        while (self.peek() or "").lower() == "or":
            self.take()
            node = ("or", node, self.term())
        return node

    def term(self):
        node = self.factor()
        while (self.peek() or "").lower() == "and":
            self.take()
            node = ("and", node, self.factor())
        return node

    def factor(self):
        tok = self.take()
        low = tok.lower()
        if low == "not":
            return ("not", self.factor())
        if tok == "(":
            node = self.expr()
            if self.take() != ")":
                raise ConditionError("expected ')'")
            return node
        if low in ("1", "all") and (self.peek() or "").lower() == "of":
            self.take()
            pattern = self.take()
            matched = (
                list(self.names) if pattern.lower() == "them"
                else [n for n in self.names if fnmatch.fnmatchcase(n, pattern)]
            )
            if not matched:
                raise ConditionError(f"pattern {pattern!r} matches no selection")
            return ("any" if low == "1" else "allof", matched)
        if tok not in self.names:
            raise ConditionError(f"unknown selection {tok!r}")
        return ("sel", tok)


def compile_condition(text: str, names: list[str]) -> Callable[[dict[str, bool]], bool]:
    """Compile *text* into a function mapping selection results to a verdict."""
    tree = _Parser(tokenize(text), names).parse()

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
