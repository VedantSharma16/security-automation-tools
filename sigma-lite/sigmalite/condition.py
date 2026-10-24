"""Parser/evaluator for Sigma condition expressions.

Grammar (precedence low -> high): ``or`` < ``and`` < ``not`` < atom, where an
atom is a selection name, ``(expr)``, or ``1 of <pattern>`` / ``all of <pattern>``
(pattern is a name with ``*`` wildcards, or ``them``).
"""
from __future__ import annotations

import fnmatch
import re
from typing import Callable

TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


class ConditionError(ValueError):
    pass


def tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"cannot tokenize condition at: {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], names: list[str]):
        self.t, self.i, self.names = tokens, 0, names

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        node = self.or_()
        if self.i != len(self.t):
            raise ConditionError(f"unexpected token {self.t[self.i]!r}")
        return node

    def or_(self):
        node = self.and_()
        while self.peek() == "or":
            self.take()
            node = ("or", node, self.and_())
        return node

    def and_(self):
        node = self.not_()
        while self.peek() == "and":
            self.take()
            node = ("and", node, self.not_())
        return node

    def not_(self):
        if self.peek() == "not":
            self.take()
            return ("not", self.not_())
        return self.atom()

    def atom(self):
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        if tok == "(":
            self.take()
            node = self.or_()
            if self.peek() != ")":
                raise ConditionError("missing closing parenthesis")
            self.take()
            return node
        if tok in ("1", "all") and self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            quant = "any" if self.take() == "1" else "all"
            self.take()
            if self.i >= len(self.t):
                raise ConditionError("'of' needs a selection pattern")
            pattern = self.take()
            matched = self.names if pattern.lower() == "them" else fnmatch.filter(self.names, pattern)
            if not matched:
                raise ConditionError(f"pattern {pattern!r} matches no selection")
            return (quant, matched)
        name = self.take()
        if name not in self.names:
            raise ConditionError(f"unknown selection {name!r}")
        return ("sel", name)


def compile_condition(text: str, names: list[str]) -> Callable[[dict[str, bool]], bool]:
    """Compile *text* into a function taking {selection_name: matched}."""
    tree = _Parser(tokenize(text), names).parse()

    def ev(node, r):
        kind = node[0]
        if kind == "sel":
            return r[node[1]]
        if kind == "not":
            return not ev(node[1], r)
        if kind == "and":
            return ev(node[1], r) and ev(node[2], r)
        if kind == "or":
            return ev(node[1], r) or ev(node[2], r)
        if kind == "any":
            return any(r[n] for n in node[1])
        return all(r[n] for n in node[1])

    return lambda results: ev(tree, results)
