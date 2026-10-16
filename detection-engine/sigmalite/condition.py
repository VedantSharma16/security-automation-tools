"""Parser/evaluator for rule conditions.

Grammar (precedence: not > and > or)::

    expr    := term ("or" term)*
    term    := factor ("and" factor)*
    factor  := "not" factor | "(" expr ")" | quant | NAME
    quant   := ("1" | "all") "of" (NAME_GLOB | "them")
"""

from __future__ import annotations

import fnmatch
import re
from typing import Callable

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


class ConditionError(ValueError):
    pass


def _tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"unexpected character at {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    if not tokens:
        raise ConditionError("empty condition")
    return tokens


class Condition:
    def __init__(self, text: str, names: set[str]):
        self.text = text
        self._names = names
        self._tokens = _tokenize(text)
        self._i = 0
        self._ast = self._expr()
        if self._i != len(self._tokens):
            raise ConditionError(f"unexpected token {self._tokens[self._i]!r}")

    # ---- parsing -------------------------------------------------------
    def _peek(self) -> str | None:
        return self._tokens[self._i] if self._i < len(self._tokens) else None

    def _next(self) -> str:
        tok = self._peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        self._i += 1
        return tok

    def _expr(self):
        node = self._term()
        while (self._peek() or "").lower() == "or":
            self._next()
            node = ("or", node, self._term())
        return node

    def _term(self):
        node = self._factor()
        while (self._peek() or "").lower() == "and":
            self._next()
            node = ("and", node, self._factor())
        return node

    def _factor(self):
        tok = self._next()
        low = tok.lower()
        if low == "not":
            return ("not", self._factor())
        if tok == "(":
            node = self._expr()
            if self._next() != ")":
                raise ConditionError("missing closing parenthesis")
            return node
        if low in ("1", "all") and (self._peek() or "").lower() == "of":
            self._next()
            target = self._next()
            pattern = "*" if target.lower() == "them" else target
            hits = sorted(n for n in self._names if fnmatch.fnmatchcase(n, pattern))
            if not hits:
                raise ConditionError(f"'{tok} of {target}' matches no selections")
            return ("any" if low == "1" else "every", hits)
        if tok in self._names:
            return ("sel", tok)
        raise ConditionError(f"unknown selection {tok!r}")

    # ---- evaluation ----------------------------------------------------
    def evaluate(self, hit: Callable[[str], bool]) -> bool:
        def ev(n):
            kind = n[0]
            if kind == "sel":
                return hit(n[1])
            if kind == "not":
                return not ev(n[1])
            if kind == "and":
                return ev(n[1]) and ev(n[2])
            if kind == "or":
                return ev(n[1]) or ev(n[2])
            if kind == "any":
                return any(hit(x) for x in n[1])
            return all(hit(x) for x in n[1])

        return ev(self._ast)
