"""Parser/evaluator for Sigma ``condition`` expressions.

Grammar (lowest to highest precedence)::

    expr    := and_expr ('or' and_expr)*
    and_expr:= not_expr ('and' not_expr)*
    not_expr:= 'not' not_expr | atom
    atom    := '(' expr ')' | quantifier | IDENT
    quantifier := ('1' | 'all') 'of' (IDENT_PATTERN | 'them')
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Callable

TOKEN_RE = re.compile(r"\s*(\(|\)|[^\s()]+)")


class ConditionError(ValueError):
    pass


def tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m:
            raise ConditionError(f"cannot tokenize condition at: {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


@dataclass
class Ref:
    name: str


@dataclass
class Quant:
    mode: str  # "any" or "all"
    pattern: str  # glob over selection names, or "them"


@dataclass
class Not:
    node: object


@dataclass
class BoolOp:
    op: str  # "and" / "or"
    left: object
    right: object


class _Parser:
    def __init__(self, tokens: list[str]):
        self.t = tokens
        self.i = 0

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

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
        node = self.and_expr()
        while (self.peek() or "").lower() == "or":
            self.take()
            node = BoolOp("or", node, self.and_expr())
        return node

    def and_expr(self):
        node = self.not_expr()
        while (self.peek() or "").lower() == "and":
            self.take()
            node = BoolOp("and", node, self.not_expr())
        return node

    def not_expr(self):
        if (self.peek() or "").lower() == "not":
            self.take()
            return Not(self.not_expr())
        return self.atom()

    def atom(self):
        tok = self.take()
        if tok == "(":
            node = self.expr()
            if self.take() != ")":
                raise ConditionError("missing closing parenthesis")
            return node
        if tok == ")":
            raise ConditionError("unexpected ')'")
        if tok.lower() in ("and", "or", "not"):
            raise ConditionError(f"unexpected operator {tok!r}")
        if (self.peek() or "").lower() == "of":
            if tok.lower() not in ("1", "all", "any"):
                raise ConditionError(f"unsupported quantifier {tok!r}")
            self.take()
            return Quant("all" if tok.lower() == "all" else "any", self.take())
        return Ref(tok)


def parse_condition(text: str):
    tokens = tokenize(text)
    if not tokens:
        raise ConditionError("empty condition")
    return _Parser(tokens).parse()


def referenced_names(node) -> set[str]:
    if isinstance(node, Ref):
        return {node.name}
    if isinstance(node, Not):
        return referenced_names(node.node)
    if isinstance(node, BoolOp):
        return referenced_names(node.left) | referenced_names(node.right)
    return set()


def evaluate(node, selection_names: list[str], match: Callable[[str], bool]) -> bool:
    """Evaluate ``node``; ``match(name)`` says whether a selection matched."""
    if isinstance(node, Ref):
        return match(node.name)
    if isinstance(node, Not):
        return not evaluate(node.node, selection_names, match)
    if isinstance(node, BoolOp):
        left = evaluate(node.left, selection_names, match)
        if node.op == "and":
            return left and evaluate(node.right, selection_names, match)
        return left or evaluate(node.right, selection_names, match)
    if isinstance(node, Quant):
        names = (
            selection_names
            if node.pattern.lower() == "them"
            else [n for n in selection_names if fnmatch.fnmatchcase(n, node.pattern)]
        )
        if not names:
            return False
        results = (match(n) for n in names)
        return all(results) if node.mode == "all" else any(results)
    raise ConditionError(f"unknown node {node!r}")
