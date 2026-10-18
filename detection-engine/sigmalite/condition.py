"""Parser/evaluator for Sigma-style condition expressions.

Grammar (lowest to highest precedence): ``or`` < ``and`` < ``not`` < atom.
Atoms: a selection name, ``(expr)``, ``1 of <glob>``, ``all of <glob>``,
``1 of them`` and ``all of them``.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Callable

_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


class ConditionError(ValueError):
    pass


def _tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"cannot tokenize condition at: {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    if not tokens:
        raise ConditionError("empty condition")
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], names: list[str]):
        self.t, self.i, self.names = tokens, 0, names
        self.used: set[str] = set()

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
        left = self.and_()
        while self.peek() == "or":
            self.take()
            right = self.and_()
            left = ("or", left, right)
        return left

    def and_(self):
        left = self.not_()
        while self.peek() == "and":
            self.take()
            right = self.not_()
            left = ("and", left, right)
        return left

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
        if tok in ("1", "all") and self.i + 2 < len(self.t) and \
                self.t[self.i + 1].lower() == "of":
            quant = "any" if tok == "1" else "all"
            self.take(); self.take()
            pattern = self.take()
            matched = (self.names if pattern.lower() == "them"
                       else fnmatch.filter(self.names, pattern))
            if not matched:
                raise ConditionError(f"no selections match {pattern!r}")
            self.used.update(matched)
            return (quant, matched)
        if tok in ("and", "or", ")", "of"):
            raise ConditionError(f"unexpected token {self.take()!r}")
        name = self.take()
        if name not in self.names:
            raise ConditionError(f"unknown selection {name!r}")
        self.used.add(name)
        return ("sel", name)


def compile_condition(text: str, names: list[str]) -> tuple[Callable[[dict[str, bool]], bool], set[str]]:
    """Compile to a function over {selection_name: matched}. Also returns used names."""
    parser = _Parser(_tokenize(text), names)
    tree = parser.parse()

    def ev(node, r):
        k = node[0]
        if k == "sel":
            return r[node[1]]
        if k == "not":
            return not ev(node[1], r)
        if k == "and":
            return ev(node[1], r) and ev(node[2], r)
        if k == "or":
            return ev(node[1], r) or ev(node[2], r)
        if k == "any":
            return any(r[n] for n in node[1])
        return all(r[n] for n in node[1])

    return (lambda results: ev(tree, results)), parser.used
