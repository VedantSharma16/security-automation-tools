"""Parser/evaluator for Sigma condition expressions.

Grammar (lowest to highest precedence): ``or`` < ``and`` < ``not`` < atom, where
an atom is a selection name, ``(expr)``, or a quantifier such as
``1 of sel_*`` / ``all of them``.
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
            raise ConditionError(f"cannot tokenize condition near {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], names: list[str]):
        self.t, self.i, self.names = tokens, 0, names

    def _peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def _next(self):
        tok = self._peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        self.i += 1
        return tok

    def parse(self):
        node = self._or()
        if self._peek() is not None:
            raise ConditionError(f"unexpected token {self._peek()!r}")
        return node

    def _or(self):
        node = self._and()
        while (self._peek() or "").lower() == "or":
            self._next()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._not()
        while (self._peek() or "").lower() == "and":
            self._next()
            node = ("and", node, self._not())
        return node

    def _not(self):
        if (self._peek() or "").lower() == "not":
            self._next()
            return ("not", self._not())
        return self._atom()

    def _atom(self):
        tok = self._next()
        if tok == "(":
            node = self._or()
            if self._next() != ")":
                raise ConditionError("missing closing parenthesis")
            return node
        if tok.lower() in ("all", "1") and (self._peek() or "").lower() == "of":
            self._next()
            pattern = self._next()
            if pattern.lower() == "them":
                matched = list(self.names)
            else:
                matched = fnmatch.filter(self.names, pattern)
            if not matched:
                raise ConditionError(f"quantifier pattern {pattern!r} matches no selection")
            return ("all" if tok.lower() == "all" else "any", matched)
        if tok.lower() in ("and", "or", "not", ")", "of"):
            raise ConditionError(f"unexpected token {tok!r}")
        if tok not in self.names:
            raise ConditionError(f"condition references unknown selection {tok!r}")
        return ("sel", tok)


def compile_condition(text: str, names: list[str]) -> Callable[[dict[str, bool]], bool]:
    """Compile *text* into a function taking ``{selection_name: matched}``."""
    ast = _Parser(_tokenize(text), names).parse()

    def evaluate(node, results):
        kind = node[0]
        if kind == "sel":
            return results[node[1]]
        if kind == "not":
            return not evaluate(node[1], results)
        if kind == "and":
            return evaluate(node[1], results) and evaluate(node[2], results)
        if kind == "or":
            return evaluate(node[1], results) or evaluate(node[2], results)
        if kind == "all":
            return all(results[n] for n in node[1])
        return any(results[n] for n in node[1])

    return lambda results: evaluate(ast, results)
