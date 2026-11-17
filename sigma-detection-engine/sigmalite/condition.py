"""Parser and evaluator for Sigma ``condition`` expressions.

Supported grammar (case-insensitive keywords)::

    expr       := or_expr
    or_expr    := and_expr ("or" and_expr)*
    and_expr   := not_expr ("and" not_expr)*
    not_expr   := "not" not_expr | atom
    atom       := "(" expr ")" | quantifier | IDENT
    quantifier := ("1" | "any" | "all") "of" (PATTERN | "them")

``PATTERN`` may contain ``*`` wildcards (``1 of selection_*``). ``them``
refers to every selection whose name does not start with an underscore,
matching the Sigma specification.

The legacy aggregation syntax (``selection | count() > 5``) is explicitly
rejected with a clear error rather than silently mis-evaluated.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence, Union


class ConditionError(ValueError):
    """Raised when a condition string cannot be parsed or references unknown selections."""


# --------------------------------------------------------------------------- AST


@dataclass(frozen=True)
class Ref:
    name: str


@dataclass(frozen=True)
class Not:
    operand: "Node"


@dataclass(frozen=True)
class And:
    operands: tuple["Node", ...]


@dataclass(frozen=True)
class Or:
    operands: tuple["Node", ...]


@dataclass(frozen=True)
class Quantified:
    quantifier: str  # "any" | "all"
    names: tuple[str, ...]


Node = Union[Ref, Not, And, Or, Quantified]

# --------------------------------------------------------------------------- lexer

_TOKEN_RE = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*\-.]+|\S)")
_KEYWORDS = {"and", "or", "not", "of", "them", "all", "any"}


def _tokenize(text: str) -> list[str]:
    if "|" in text:
        raise ConditionError(
            "aggregation conditions ('| count() ...') are not supported; "
            "use a correlation rule or post-process alerts instead"
        )
    tokens: list[str] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:  # pragma: no cover - regex matches any non-space char
            raise ConditionError(f"unexpected input at {pos}: {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


# --------------------------------------------------------------------------- parser


class _Parser:
    def __init__(self, tokens: Sequence[str], selections: Sequence[str]):
        self.tokens = list(tokens)
        self.pos = 0
        self.selections = list(selections)

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def peek_kw(self) -> str | None:
        tok = self.peek()
        return tok.lower() if tok is not None else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        self.pos += 1
        return tok

    def expect(self, kw: str) -> None:
        tok = self.take()
        if tok.lower() != kw:
            raise ConditionError(f"expected {kw!r}, got {tok!r}")

    def parse(self) -> Node:
        if not self.tokens:
            raise ConditionError("empty condition")
        node = self.or_expr()
        if self.peek() is not None:
            raise ConditionError(f"unexpected token {self.peek()!r}")
        return node

    def or_expr(self) -> Node:
        parts = [self.and_expr()]
        while self.peek_kw() == "or":
            self.take()
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else Or(tuple(parts))

    def and_expr(self) -> Node:
        parts = [self.not_expr()]
        while self.peek_kw() == "and":
            self.take()
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else And(tuple(parts))

    def not_expr(self) -> Node:
        if self.peek_kw() == "not":
            self.take()
            return Not(self.not_expr())
        return self.atom()

    def atom(self) -> Node:
        tok = self.take()
        low = tok.lower()
        if tok == "(":
            node = self.or_expr()
            self.expect(")")
            return node
        if low in {"1", "any", "all"} and self.peek_kw() == "of":
            self.take()
            target = self.take()
            names = self._resolve(target)
            return Quantified("all" if low == "all" else "any", names)
        if low in _KEYWORDS or tok == ")":
            raise ConditionError(f"unexpected keyword {tok!r}")
        if tok not in self.selections:
            raise ConditionError(f"condition references unknown selection {tok!r}")
        return Ref(tok)

    def _resolve(self, target: str) -> tuple[str, ...]:
        if target.lower() == "them":
            names = [s for s in self.selections if not s.startswith("_")]
        else:
            names = [s for s in self.selections if fnmatch.fnmatchcase(s, target)]
        if not names:
            raise ConditionError(f"pattern {target!r} matches no selections")
        return tuple(names)


def parse_condition(condition: str | Sequence[str], selections: Sequence[str]) -> Node:
    """Parse a condition (or list of conditions, OR-ed together) into an AST."""
    if isinstance(condition, str):
        return _Parser(_tokenize(condition), selections).parse()
    nodes = tuple(parse_condition(c, selections) for c in condition)
    if not nodes:
        raise ConditionError("empty condition list")
    return nodes[0] if len(nodes) == 1 else Or(nodes)


def evaluate(node: Node, resolve: Callable[[str], bool] | Mapping[str, bool]) -> bool:
    """Evaluate an AST. ``resolve`` maps a selection name to its match result.

    Passing a callable lets the engine evaluate selections lazily, so
    short-circuiting ``and``/``or`` skips work on non-matching events.
    """
    get = resolve.__getitem__ if isinstance(resolve, Mapping) else resolve
    if isinstance(node, Ref):
        return get(node.name)
    if isinstance(node, Not):
        return not evaluate(node.operand, get)
    if isinstance(node, And):
        return all(evaluate(n, get) for n in node.operands)
    if isinstance(node, Or):
        return any(evaluate(n, get) for n in node.operands)
    if isinstance(node, Quantified):
        fn = all if node.quantifier == "all" else any
        return fn(get(n) for n in node.names)
    raise TypeError(f"unknown node {node!r}")  # pragma: no cover
