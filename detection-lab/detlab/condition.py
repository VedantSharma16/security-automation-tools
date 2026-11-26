"""Recursive-descent parser for Sigma ``condition`` expressions.

Grammar (case-insensitive keywords)::

    expr     := and_expr ("or" and_expr)*
    and_expr := not_expr ("and" not_expr)*
    not_expr := "not" not_expr | atom
    atom     := "(" expr ")"
              | ("1" | "any" | "all") "of" (PATTERN | "them")
              | IDENTIFIER

Patterns may use ``*`` wildcards (``1 of selection_*``). ``them`` refers to
every selection whose name does not start with an underscore, as in the
Sigma specification. Aggregation expressions (``| count() > 5``) are
deprecated in Sigma and are rejected with a clear error.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Callable, Union

from .matcher import RuleSyntaxError

_TOKEN_RE = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*\-.]+|\||\S)")


@dataclass(frozen=True)
class Ref:
    name: str


@dataclass(frozen=True)
class Not:
    operand: "Node"


@dataclass(frozen=True)
class BoolOp:
    op: str  # "and" | "or"
    operands: tuple["Node", ...]


@dataclass(frozen=True)
class OfQuantifier:
    quantifier: str  # "any" | "all"
    names: tuple[str, ...]
    source: str


Node = Union[Ref, Not, BoolOp, OfQuantifier]


def tokenize(text: str) -> list[str]:
    tokens = [m.group(1) for m in _TOKEN_RE.finditer(text) if m.group(1).strip()]
    if "|" in tokens:
        raise RuleSyntaxError(
            "aggregation conditions ('| count() ...') are deprecated in Sigma and not supported; "
            "use a correlation rule or post-process alerts instead"
        )
    return tokens


class _Parser:
    def __init__(self, text: str, identifiers: list[str]):
        self.tokens = tokenize(text)
        self.pos = 0
        self.identifiers = identifiers
        self.text = text

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def advance(self) -> str:
        tok = self.peek()
        if tok is None:
            raise RuleSyntaxError(f"unexpected end of condition: {self.text!r}")
        self.pos += 1
        return tok

    def parse(self) -> Node:
        if not self.tokens:
            raise RuleSyntaxError("condition is empty")
        node = self.expr()
        if self.peek() is not None:
            raise RuleSyntaxError(f"unexpected token {self.peek()!r} in condition {self.text!r}")
        return node

    def expr(self) -> Node:
        operands = [self.and_expr()]
        while (tok := self.peek()) and tok.lower() == "or":
            self.advance()
            operands.append(self.and_expr())
        return operands[0] if len(operands) == 1 else BoolOp("or", tuple(operands))

    def and_expr(self) -> Node:
        operands = [self.not_expr()]
        while (tok := self.peek()) and tok.lower() == "and":
            self.advance()
            operands.append(self.not_expr())
        return operands[0] if len(operands) == 1 else BoolOp("and", tuple(operands))

    def not_expr(self) -> Node:
        tok = self.peek()
        if tok and tok.lower() == "not":
            self.advance()
            return Not(self.not_expr())
        return self.atom()

    def atom(self) -> Node:
        tok = self.advance()
        low = tok.lower()
        if tok == "(":
            node = self.expr()
            if self.advance() != ")":
                raise RuleSyntaxError(f"missing ')' in condition {self.text!r}")
            return node
        if low in {"1", "any", "all"} and (nxt := self.peek()) and nxt.lower() == "of":
            self.advance()
            target = self.advance()
            return self._quantifier("all" if low == "all" else "any", target)
        if low in {"and", "or", "not", "of", ")"}:
            raise RuleSyntaxError(f"unexpected keyword {tok!r} in condition {self.text!r}")
        if tok not in self.identifiers:
            raise RuleSyntaxError(f"condition references undefined selection '{tok}'")
        return Ref(tok)

    def _quantifier(self, quantifier: str, target: str) -> OfQuantifier:
        if target.lower() == "them":
            names = [i for i in self.identifiers if not i.startswith("_")]
        else:
            names = [i for i in self.identifiers if fnmatch.fnmatchcase(i, target)]
        if not names:
            raise RuleSyntaxError(f"'{quantifier} of {target}' matches no selections")
        return OfQuantifier(quantifier, tuple(names), target)


def parse_condition(text: str, identifiers: list[str]) -> Node:
    return _Parser(str(text), list(identifiers)).parse()


def evaluate(node: Node, resolve: Callable[[str], bool]) -> bool:
    """Evaluate a parsed condition; ``resolve`` answers "did selection X match?"."""
    if isinstance(node, Ref):
        return resolve(node.name)
    if isinstance(node, Not):
        return not evaluate(node.operand, resolve)
    if isinstance(node, BoolOp):
        results = (evaluate(op, resolve) for op in node.operands)
        return all(results) if node.op == "and" else any(results)
    if isinstance(node, OfQuantifier):
        results = (resolve(name) for name in node.names)
        return all(results) if node.quantifier == "all" else any(results)
    raise TypeError(f"unknown node {node!r}")  # pragma: no cover


def referenced(node: Node) -> set[str]:
    """All selection names a condition can touch (used by the linter)."""
    if isinstance(node, Ref):
        return {node.name}
    if isinstance(node, Not):
        return referenced(node.operand)
    if isinstance(node, BoolOp):
        return set().union(*(referenced(op) for op in node.operands))
    if isinstance(node, OfQuantifier):
        return set(node.names)
    return set()  # pragma: no cover
