"""Parser/evaluator for Sigma ``condition`` expressions.

Grammar (lowest to highest precedence)::

    expr    := or_expr
    or_expr := and_expr ('or' and_expr)*
    and_expr:= not_expr ('and' not_expr)*
    not_expr:= 'not' not_expr | atom
    atom    := '(' expr ')' | quant 'of' target | IDENT
    quant   := '1' | 'all'
    target  := 'them' | IDENT_WITH_OPTIONAL_WILDCARD
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Callable

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")
_KEYWORDS = {"and", "or", "not", "of"}


class ConditionError(ValueError):
    """Raised for malformed condition strings."""


def tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"unexpected character at {pos}: {text[pos:pos+10]!r}")
        tokens.append(m.group(1))
        pos = m.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    if not tokens:
        raise ConditionError("empty condition")
    return tokens


@dataclass
class Node:
    kind: str  # name | and | or | not | of
    value: str | None = None
    children: tuple["Node", ...] = ()
    quant: str | None = None

    def names(self) -> set[str]:
        """Selection identifiers referenced (wildcards unexpanded)."""
        if self.kind == "name":
            return {self.value}
        if self.kind == "of":
            return {self.value} if self.value != "them" else set()
        out: set[str] = set()
        for c in self.children:
            out |= c.names()
        return out


class _Parser:
    def __init__(self, tokens: list[str]):
        self.t, self.i = tokens, 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self):
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        self.i += 1
        return tok

    def parse(self) -> Node:
        node = self.or_expr()
        if self.peek() is not None:
            raise ConditionError(f"unexpected token {self.peek()!r}")
        return node

    def or_expr(self):
        node = self.and_expr()
        while self.peek() == "or":
            self.take()
            node = Node("or", children=(node, self.and_expr()))
        return node

    def and_expr(self):
        node = self.not_expr()
        while self.peek() == "and":
            self.take()
            node = Node("and", children=(node, self.not_expr()))
        return node

    def not_expr(self):
        if self.peek() == "not":
            self.take()
            return Node("not", children=(self.not_expr(),))
        return self.atom()

    def atom(self):
        tok = self.take()
        if tok == "(":
            node = self.or_expr()
            if self.take() != ")":
                raise ConditionError("expected ')'")
            return node
        if tok in (")",) or tok in _KEYWORDS:
            raise ConditionError(f"unexpected token {tok!r}")
        if tok in ("1", "all") and self.peek() == "of":
            self.take()
            target = self.take()
            if target in _KEYWORDS or target in "()":
                raise ConditionError("expected selection pattern after 'of'")
            return Node("of", value=target, quant=tok)
        return Node("name", value=tok)


def parse(text: str) -> Node:
    return _Parser(tokenize(text)).parse()


def evaluate(node: Node, selections: dict[str, Callable[[], bool]]) -> bool:
    """Evaluate ``node``; ``selections`` maps name -> lazy matcher."""
    if node.kind == "name":
        if node.value not in selections:
            raise ConditionError(f"unknown selection {node.value!r}")
        return selections[node.value]()
    if node.kind == "and":
        return all(evaluate(c, selections) for c in node.children)
    if node.kind == "or":
        return any(evaluate(c, selections) for c in node.children)
    if node.kind == "not":
        return not evaluate(node.children[0], selections)
    if node.kind == "of":
        names = (list(selections) if node.value == "them"
                 else [n for n in selections if fnmatch.fnmatchcase(n, node.value)])
        if not names:
            raise ConditionError(f"no selections match {node.value!r}")
        results = (selections[n]() for n in names)
        return all(results) if node.quant == "all" else any(results)
    raise ConditionError(f"bad node {node.kind}")
