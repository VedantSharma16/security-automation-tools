"""Parser and evaluator for Sigma ``condition`` expressions.

Grammar (lowest to highest precedence)::

    expr   := term ("or" term)*
    term   := factor ("and" factor)*
    factor := "not" factor | "(" expr ")" | quantifier | NAME
    quantifier := ("1" | "all") "of" (NAME-with-optional-* | "them")
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Callable, Iterable

_TOKEN_RE = re.compile(r"\s*(\(|\)|[^\s()]+)")
_KEYWORDS = {"and", "or", "not", "of", "1", "all"}


class ConditionError(ValueError):
    """Raised when a condition expression is malformed."""


@dataclass(frozen=True)
class Ref:
    name: str


@dataclass(frozen=True)
class Not:
    operand: "Node"


@dataclass(frozen=True)
class And:
    operands: tuple


@dataclass(frozen=True)
class Or:
    operands: tuple


@dataclass(frozen=True)
class Quantified:
    quantifier: str  # "1" or "all"
    pattern: str  # selection glob, or "them"


Node = Ref | Not | And | Or | Quantified


def _tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise ConditionError(f"cannot tokenize condition near {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.i = 0

    def peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def next(self) -> str:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        self.i += 1
        return tok

    def parse(self) -> Node:
        node = self.expr()
        if self.peek() is not None:
            raise ConditionError(f"unexpected token {self.peek()!r}")
        return node

    def expr(self) -> Node:
        parts = [self.term()]
        while (self.peek() or "").lower() == "or":
            self.next()
            parts.append(self.term())
        return parts[0] if len(parts) == 1 else Or(tuple(parts))

    def term(self) -> Node:
        parts = [self.factor()]
        while (self.peek() or "").lower() == "and":
            self.next()
            parts.append(self.factor())
        return parts[0] if len(parts) == 1 else And(tuple(parts))

    def factor(self) -> Node:
        tok = self.next()
        low = tok.lower()
        if low == "not":
            return Not(self.factor())
        if tok == "(":
            node = self.expr()
            if self.next() != ")":
                raise ConditionError("missing closing parenthesis")
            return node
        if low in ("1", "all") and (self.peek() or "").lower() == "of":
            self.next()
            return Quantified(low, self.next())
        if low in _KEYWORDS or tok == ")":
            raise ConditionError(f"unexpected token {tok!r}")
        return Ref(tok)


def parse_condition(text: str) -> Node:
    tokens = _tokenize(text)
    if not tokens:
        raise ConditionError("empty condition")
    return _Parser(tokens).parse()


def referenced_names(node: Node) -> set[str]:
    """Selection names (and globs) a parsed condition refers to."""
    if isinstance(node, Ref):
        return {node.name}
    if isinstance(node, Quantified):
        return set() if node.pattern == "them" else {node.pattern}
    if isinstance(node, Not):
        return referenced_names(node.operand)
    return set().union(*(referenced_names(o) for o in node.operands))


def _expand(pattern: str, names: Iterable[str]) -> list[str]:
    names = list(names)
    return names if pattern == "them" else fnmatch.filter(names, pattern)


def evaluate_condition(node: Node, selections: dict[str, Callable[[], bool]]) -> bool:
    """Evaluate ``node``; ``selections`` maps name -> zero-arg thunk (lazy)."""
    if isinstance(node, Ref):
        if node.name not in selections:
            raise ConditionError(f"condition references unknown selection {node.name!r}")
        return selections[node.name]()
    if isinstance(node, Not):
        return not evaluate_condition(node.operand, selections)
    if isinstance(node, And):
        return all(evaluate_condition(o, selections) for o in node.operands)
    if isinstance(node, Or):
        return any(evaluate_condition(o, selections) for o in node.operands)
    matched = _expand(node.pattern, selections)
    if not matched:
        raise ConditionError(f"pattern {node.pattern!r} matches no selections")
    fn = all if node.quantifier == "all" else any
    return fn(selections[n]() for n in matched)
