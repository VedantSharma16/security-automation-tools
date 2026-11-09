"""Parser/evaluator for Sigma ``condition`` expressions.

Grammar (precedence low -> high):
    expr   := and_ ('or' and_)*
    and_   := not_ ('and' not_)*
    not_   := 'not' not_ | atom
    atom   := '(' expr ')' | ('1'|'all') 'of' (pattern|'them') | identifier
Patterns may end in ``*`` (e.g. ``selection_*``).
"""
from __future__ import annotations

import fnmatch
import re
from typing import Callable, Dict

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*.\-]+)")
KEYWORDS = {"and", "or", "not", "of", "them"}


class ConditionError(ValueError):
    pass


def _tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"unexpected character at {pos}: {text[pos:pos+10]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], names: set[str]):
        self.t, self.i, self.names = tokens, 0, names

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        node = self.expr()
        if self.i != len(self.t):
            raise ConditionError(f"unexpected token {self.t[self.i]!r}")
        return node

    def expr(self):
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
            node = self.expr()
            if self.peek() != ")":
                raise ConditionError("missing closing parenthesis")
            self.take()
            return node
        if tok in ("1", "all") and self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            self.take(); self.take()
            if self.i >= len(self.t):
                raise ConditionError("'of' needs a target")
            pat = self.take()
            matched = (sorted(self.names) if pat.lower() == "them"
                       else sorted(n for n in self.names if fnmatch.fnmatchcase(n, pat)))
            if not matched:
                raise ConditionError(f"pattern {pat!r} matches no selections")
            return ("all" if tok == "all" else "any", matched)
        if tok in KEYWORDS or tok == ")":
            raise ConditionError(f"unexpected token {tok!r}")
        name = self.take()
        if name not in self.names:
            raise ConditionError(f"unknown selection {name!r}")
        return ("sel", name)


def parse(text: str, names: set[str]):
    return _Parser(_tokenize(text), names).parse()


def evaluate(node, lookup: Callable[[str], bool]) -> bool:
    kind = node[0]
    if kind == "sel":
        return lookup(node[1])
    if kind == "not":
        return not evaluate(node[1], lookup)
    if kind == "and":
        return evaluate(node[1], lookup) and evaluate(node[2], lookup)
    if kind == "or":
        return evaluate(node[1], lookup) or evaluate(node[2], lookup)
    if kind == "any":
        return any(lookup(n) for n in node[1])
    if kind == "all":
        return all(lookup(n) for n in node[1])
    raise ConditionError(f"bad node {kind}")
