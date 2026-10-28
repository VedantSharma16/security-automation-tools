"""Parser and evaluator for Sigma ``condition`` expressions.

Grammar (lowest to highest precedence)::

    expr    := and_expr ('or' and_expr)*
    and_expr:= not_expr ('and' not_expr)*
    not_expr:= 'not' not_expr | atom
    atom    := '(' expr ')' | quantifier | NAME
    quantifier := ('1' | 'all') 'of' (NAME_GLOB | 'them')
"""

from __future__ import annotations

import fnmatch
import re
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


class _Parser:
    def __init__(self, tokens: list[str], names: list[str]):
        self.tokens, self.names, self.i = tokens, names, 0

    def peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        self.i += 1
        return tok

    def parse(self):
        node = self.or_expr()
        if self.peek() is not None:
            raise ConditionError(f"unexpected token {self.peek()!r}")
        return node

    def or_expr(self):
        node = self.and_expr()
        while (self.peek() or "").lower() == "or":
            self.take()
            node = ("or", node, self.and_expr())
        return node

    def and_expr(self):
        node = self.not_expr()
        while (self.peek() or "").lower() == "and":
            self.take()
            node = ("and", node, self.not_expr())
        return node

    def not_expr(self):
        if (self.peek() or "").lower() == "not":
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
        if tok.lower() in ("all", "1") and (self.peek() or "").lower() == "of":
            self.take()
            target = self.take()
            matched = (
                list(self.names) if target.lower() == "them"
                else [n for n in self.names if fnmatch.fnmatchcase(n, target)]
            )
            if not matched:
                raise ConditionError(f"'{tok} of {target}' matches no selection")
            return ("all_of" if tok.lower() == "all" else "any_of", matched)
        if tok not in self.names:
            raise ConditionError(f"unknown selection {tok!r}")
        return ("name", tok)


def parse_condition(text: str, names: list[str]):
    return _Parser(tokenize(text), names).parse()


def evaluate(node, results: Callable[[str], bool]) -> bool:
    kind = node[0]
    if kind == "name":
        return results(node[1])
    if kind == "not":
        return not evaluate(node[1], results)
    if kind == "and":
        return evaluate(node[1], results) and evaluate(node[2], results)
    if kind == "or":
        return evaluate(node[1], results) or evaluate(node[2], results)
    if kind == "all_of":
        return all(results(n) for n in node[1])
    if kind == "any_of":
        return any(results(n) for n in node[1])
    raise ConditionError(f"bad node {node!r}")
