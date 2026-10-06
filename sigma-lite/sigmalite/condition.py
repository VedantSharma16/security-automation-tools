"""Parser/evaluator for Sigma condition expressions.

Grammar (lowest to highest precedence)::

    expr    := or_expr
    or_expr := and_expr ('or' and_expr)*
    and_expr:= not_expr ('and' not_expr)*
    not_expr:= 'not' not_expr | atom
    atom    := '(' expr ')' | quantifier | NAME
    quantifier := ('1' | 'all') 'of' (NAME_GLOB | 'them')

Parsing is recursive descent into a small AST of tuples so a rule's
condition is validated once at load time and evaluated cheaply per event.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Callable

_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


class ConditionError(ValueError):
    """Raised when a condition expression is malformed."""


def _tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"cannot tokenize near {text[pos:pos + 10]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.i = 0

    def peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        self.i += 1
        return tok

    def parse(self):
        if not self.tokens:
            raise ConditionError("empty condition")
        node = self.or_expr()
        if self.peek() is not None:
            raise ConditionError(f"unexpected token {self.peek()!r}")
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
        tok = self.take()
        if tok == "(":
            node = self.or_expr()
            if self.take() != ")":
                raise ConditionError("missing closing parenthesis")
            return node
        if tok in ("and", "or", ")"):
            raise ConditionError(f"unexpected token {tok!r}")
        if tok in ("1", "all") and self.peek() == "of":
            self.take()
            return ("of", tok, self.take())
        return ("name", tok)


def parse_condition(text: str):
    return _Parser(_tokenize(text)).parse()


def referenced_names(node) -> set[str]:
    """Selection names / globs referenced by an AST (for linting)."""
    kind = node[0]
    if kind == "name":
        return {node[1]}
    if kind == "of":
        return set() if node[2] == "them" else {node[2]}
    return set().union(*(referenced_names(c) for c in node[1:]))


def evaluate(node, results: dict[str, bool]) -> bool:
    """Evaluate an AST given a mapping of selection name -> matched."""
    kind = node[0]
    if kind == "name":
        if node[1] not in results:
            raise ConditionError(f"unknown selection {node[1]!r}")
        return results[node[1]]
    if kind == "not":
        return not evaluate(node[1], results)
    if kind == "and":
        return evaluate(node[1], results) and evaluate(node[2], results)
    if kind == "or":
        return evaluate(node[1], results) or evaluate(node[2], results)
    if kind == "of":
        _, quant, target = node
        names = (
            list(results)
            if target == "them"
            else [n for n in results if fnmatch.fnmatchcase(n, target)]
        )
        if not names:
            raise ConditionError(f"no selections match {target!r}")
        hits = [results[n] for n in names]
        return any(hits) if quant == "1" else all(hits)
    raise ConditionError(f"bad node {kind!r}")  # pragma: no cover


Evaluator = Callable[[dict[str, bool]], bool]
