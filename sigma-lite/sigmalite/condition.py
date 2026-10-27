"""Safe parser/evaluator for Sigma-style condition expressions.

Grammar (lowest to highest precedence):
    expr    := or_expr
    or_expr := and_expr ('or' and_expr)*
    and_expr:= not_expr ('and' not_expr)*
    not_expr:= 'not' not_expr | atom
    atom    := '(' expr ')' | quantifier | IDENT
    quantifier := ('1' | 'all') 'of' (IDENT_GLOB | 'them')

No eval() is used; conditions are tokenised and parsed into a small AST.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")
_KEYWORDS = {"and", "or", "not", "of"}


class ConditionError(ValueError):
    pass


def tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"unexpected character {text[pos]!r} in condition")
        tokens.append(m.group(1))
        pos = m.end()
    if not tokens:
        raise ConditionError("empty condition")
    return tokens


@dataclass
class Node:
    kind: str  # 'name' | 'not' | 'and' | 'or' | 'of'
    value: object = None
    children: tuple = ()


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

    def or_expr(self) -> Node:
        parts = [self.and_expr()]
        while self.peek() == "or":
            self.take()
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else Node("or", children=tuple(parts))

    def and_expr(self) -> Node:
        parts = [self.not_expr()]
        while self.peek() == "and":
            self.take()
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else Node("and", children=tuple(parts))

    def not_expr(self) -> Node:
        if self.peek() == "not":
            self.take()
            return Node("not", children=(self.not_expr(),))
        return self.atom()

    def atom(self) -> Node:
        tok = self.take()
        if tok == "(":
            node = self.or_expr()
            if self.take() != ")":
                raise ConditionError("expected ')'")
            return node
        if tok in (")",) or tok in _KEYWORDS - {"of"}:
            raise ConditionError(f"unexpected token {tok!r}")
        if self.peek() == "of" and (tok == "all" or tok == "1"):
            self.take()
            target = self.take()
            if target in _KEYWORDS or target in "()":
                raise ConditionError("expected selection pattern after 'of'")
            return Node("of", value=(tok, target))
        return Node("name", value=tok)


def parse(text: str) -> Node:
    return _Parser(tokenize(text)).parse()


def names_in(node: Node) -> set[str]:
    """Selection identifiers/patterns referenced (for validation)."""
    if node.kind == "name":
        return {node.value}
    if node.kind == "of":
        return {node.value[1]}
    out: set[str] = set()
    for c in node.children:
        out |= names_in(c)
    return out


def evaluate(node: Node, results: dict[str, bool]) -> bool:
    """Evaluate against a mapping of selection name -> bool."""
    k = node.kind
    if k == "name":
        if node.value not in results:
            raise ConditionError(f"unknown selection {node.value!r}")
        return results[node.value]
    if k == "not":
        return not evaluate(node.children[0], results)
    if k == "and":
        return all(evaluate(c, results) for c in node.children)
    if k == "or":
        return any(evaluate(c, results) for c in node.children)
    quant, pattern = node.value
    chosen = list(results.values()) if pattern == "them" else [
        v for n, v in results.items() if fnmatch.fnmatchcase(n, pattern)
    ]
    if not chosen:
        raise ConditionError(f"pattern {pattern!r} matches no selections")
    return all(chosen) if quant == "all" else any(chosen)
