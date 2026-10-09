"""Parser/evaluator for Sigma-style condition expressions.

Grammar (lowest to highest precedence)::

    expr    := or_expr
    or_expr := and_expr ("or" and_expr)*
    and_expr:= not_expr ("and" not_expr)*
    not_expr:= "not" not_expr | atom
    atom    := "(" expr ")" | quantifier | NAME
    quantifier := ("1" | "all") "of" (NAME_GLOB | "them")
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Callable, Mapping

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")
_KEYWORDS = {"and", "or", "not", "of"}


class ConditionError(ValueError):
    """Raised for malformed condition expressions."""


def tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"unexpected character at {pos}: {text[pos:pos + 10]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    if not tokens:
        raise ConditionError("empty condition")
    return tokens


@dataclass
class Node:
    kind: str  # name | not | and | or | quant
    value: object = None
    children: tuple = ()


class _Parser:
    def __init__(self, tokens: list[str]):
        self.t, self.i = tokens, 0

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def next(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self) -> Node:
        node = self.or_expr()
        if self.i != len(self.t):
            raise ConditionError(f"unexpected token {self.t[self.i]!r}")
        return node

    def or_expr(self) -> Node:
        parts = [self.and_expr()]
        while self.peek() == "or":
            self.next()
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else Node("or", children=tuple(parts))

    def and_expr(self) -> Node:
        parts = [self.not_expr()]
        while self.peek() == "and":
            self.next()
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else Node("and", children=tuple(parts))

    def not_expr(self) -> Node:
        if self.peek() == "not":
            self.next()
            return Node("not", children=(self.not_expr(),))
        return self.atom()

    def atom(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        if tok == "(":
            self.next()
            node = self.or_expr()
            if self.peek() != ")":
                raise ConditionError("missing closing parenthesis")
            self.next()
            return node
        if tok in (")",) or tok in _KEYWORDS - {"of"}:
            raise ConditionError(f"unexpected token {tok!r}")
        raw = self.next()
        if self.peek() == "of":
            if raw.lower() not in ("1", "all"):
                raise ConditionError(f"unsupported quantifier {raw!r} (use '1' or 'all')")
            self.next()
            if self.peek() is None:
                raise ConditionError("quantifier needs a target")
            return Node("quant", value=(raw.lower(), self.next()))
        return Node("name", value=raw)


def parse(text: str) -> Node:
    return _Parser(tokenize(text)).parse()


def referenced_names(node: Node) -> set[str]:
    """Selection names (and globs) referenced by an expression."""
    if node.kind == "name":
        return {node.value}
    if node.kind == "quant":
        return {node.value[1]}
    out: set[str] = set()
    for c in node.children:
        out |= referenced_names(c)
    return out


def evaluate(node: Node, lookup: Callable[[str], bool], names: Mapping[str, object]) -> bool:
    """Evaluate ``node``; ``lookup`` resolves one selection name to a bool."""
    k = node.kind
    if k == "name":
        return lookup(node.value)
    if k == "not":
        return not evaluate(node.children[0], lookup, names)
    if k == "and":
        return all(evaluate(c, lookup, names) for c in node.children)
    if k == "or":
        return any(evaluate(c, lookup, names) for c in node.children)
    quant, target = node.value
    matched = list(names) if target.lower() == "them" else fnmatch.filter(list(names), target)
    if not matched:
        return False
    results = (lookup(n) for n in matched)
    return all(results) if quant == "all" else any(results)
