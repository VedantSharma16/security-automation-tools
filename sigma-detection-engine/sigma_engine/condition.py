"""Parser and evaluator for Sigma ``condition`` expressions.

Grammar (precedence low -> high)::

    expr       := and_expr ("or" and_expr)*
    and_expr   := not_expr ("and" not_expr)*
    not_expr   := "not" not_expr | primary
    primary    := "(" expr ")" | quantified | IDENT
    quantified := ("1" | "any" | "all" | INT) "of" (PATTERN | "them")

``PATTERN`` may contain ``*`` wildcards (``selection_*``). ``them`` refers to
every detection identifier that does not start with an underscore, matching
the Sigma specification.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Callable, Iterable

__all__ = ["ConditionError", "Node", "parse_condition"]


class ConditionError(ValueError):
    """Raised for malformed conditions or references to unknown identifiers."""


_TOKEN_RE = re.compile(r"\s*(\(|\)|[A-Za-z0-9_\-\*\.]+)")
_KEYWORDS = {"and", "or", "not", "of", "them", "all", "any"}


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise ConditionError(f"unexpected character at offset {pos}: {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return tokens


# --------------------------------------------------------------------------- AST


@dataclass(frozen=True)
class Node:
    """A node in the condition AST.

    ``kind`` is one of ``ident``, ``and``, ``or``, ``not``, ``of``.
    """

    kind: str
    children: tuple["Node", ...] = ()
    name: str = ""
    # for "of": minimum number of identifiers that must match (0 == all)
    quantity: int = 1
    targets: tuple[str, ...] = ()

    def evaluate(self, resolve: Callable[[str], bool]) -> bool:
        if self.kind == "ident":
            return resolve(self.name)
        if self.kind == "not":
            return not self.children[0].evaluate(resolve)
        if self.kind == "and":
            return all(c.evaluate(resolve) for c in self.children)
        if self.kind == "or":
            return any(c.evaluate(resolve) for c in self.children)
        if self.kind == "of":
            hits = sum(1 for t in self.targets if resolve(t))
            if self.quantity == 0:
                return hits == len(self.targets)
            return hits >= self.quantity
        raise ConditionError(f"unknown node kind {self.kind!r}")  # pragma: no cover

    def identifiers(self) -> set[str]:
        """Return every detection identifier this expression can touch."""
        if self.kind == "ident":
            return {self.name}
        if self.kind == "of":
            return set(self.targets)
        out: set[str] = set()
        for c in self.children:
            out |= c.identifiers()
        return out


# ------------------------------------------------------------------------ parser


class _Parser:
    def __init__(self, tokens: list[str], identifiers: Iterable[str]):
        self.tokens = tokens
        self.pos = 0
        self.identifiers = list(identifiers)

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self, expected: str | None = None) -> str:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        if expected is not None and tok.lower() != expected:
            raise ConditionError(f"expected {expected!r}, got {tok!r}")
        self.pos += 1
        return tok

    def parse(self) -> Node:
        if not self.tokens:
            raise ConditionError("empty condition")
        node = self.expr()
        if self.peek() is not None:
            raise ConditionError(f"unexpected token {self.peek()!r}")
        return node

    def expr(self) -> Node:
        parts = [self.and_expr()]
        while (self.peek() or "").lower() == "or":
            self.take()
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else Node("or", tuple(parts))

    def and_expr(self) -> Node:
        parts = [self.not_expr()]
        while (self.peek() or "").lower() == "and":
            self.take()
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else Node("and", tuple(parts))

    def not_expr(self) -> Node:
        if (self.peek() or "").lower() == "not":
            self.take()
            return Node("not", (self.not_expr(),))
        return self.primary()

    def primary(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        if tok == "(":
            self.take()
            node = self.expr()
            self.take(")")
            return node
        if tok == ")":
            raise ConditionError("unbalanced ')'")

        nxt = self.tokens[self.pos + 1] if self.pos + 1 < len(self.tokens) else None
        if nxt is not None and nxt.lower() == "of":
            return self.quantified()

        if tok.lower() in _KEYWORDS:
            raise ConditionError(f"unexpected keyword {tok!r}")
        self.take()
        if tok not in self.identifiers:
            raise ConditionError(f"condition references unknown identifier {tok!r}")
        return Node("ident", name=tok)

    def quantified(self) -> Node:
        q = self.take().lower()
        self.take("of")
        if q in ("1", "any"):
            quantity = 1
        elif q == "all":
            quantity = 0
        elif q.isdigit() and int(q) > 0:
            quantity = int(q)
        else:
            raise ConditionError(f"invalid quantifier {q!r}")

        target = self.take()
        if target.lower() == "them":
            matched = [i for i in self.identifiers if not i.startswith("_")]
        else:
            matched = [i for i in self.identifiers if fnmatch.fnmatchcase(i, target)]
        if not matched:
            raise ConditionError(f"'{q} of {target}' matches no detection identifiers")
        return Node("of", quantity=quantity, targets=tuple(matched))


def parse_condition(condition: str | list[str], identifiers: Iterable[str]) -> Node:
    """Parse a Sigma condition (string or list of strings) into an AST.

    A list of conditions is treated as a logical OR, as in the Sigma spec.
    """
    identifiers = list(identifiers)
    if isinstance(condition, list):
        if not condition:
            raise ConditionError("empty condition list")
        nodes = tuple(parse_condition(c, identifiers) for c in condition)
        return nodes[0] if len(nodes) == 1 else Node("or", nodes)
    if not isinstance(condition, str):
        raise ConditionError(f"condition must be a string, got {type(condition).__name__}")
    return _Parser(_tokenize(condition), identifiers).parse()
