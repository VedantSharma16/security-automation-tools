"""Parser/evaluator for Sigma condition expressions.

Grammar (lowest to highest precedence): ``or`` < ``and`` < ``not`` < atom, where an
atom is a selection name, ``(expr)``, or a quantifier such as ``1 of sel_*`` /
``all of them``. Parsed to a small AST once, then evaluated per event.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Callable, Mapping

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

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self):
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        self.i += 1
        return tok

    def parse(self):
        node = self.or_()
        if self.peek() is not None:
            raise ConditionError(f"unexpected token {self.peek()!r}")
        return node

    def or_(self):
        node = self.and_()
        while (self.peek() or "").lower() == "or":
            self.take()
            node = ("or", node, self.and_())
        return node

    def and_(self):
        node = self.not_()
        while (self.peek() or "").lower() == "and":
            self.take()
            node = ("and", node, self.not_())
        return node

    def not_(self):
        if (self.peek() or "").lower() == "not":
            self.take()
            return ("not", self.not_())
        return self.atom()

    def atom(self):
        tok = self.take()
        if tok == "(":
            node = self.or_()
            if self.take() != ")":
                raise ConditionError("missing closing parenthesis")
            return node
        low = tok.lower()
        if low == "all" or low.isdigit():
            if (self.peek() or "").lower() != "of":
                raise ConditionError(f"expected 'of' after {tok!r}")
            self.take()
            pattern = self.take()
            matched = self.names if pattern.lower() == "them" else fnmatch.filter(self.names, pattern)
            if not matched:
                raise ConditionError(f"pattern {pattern!r} matches no selections")
            return ("quant", None if low == "all" else int(low), tuple(matched))
        if tok in (")", "and", "or", "not"):
            raise ConditionError(f"unexpected token {tok!r}")
        if tok not in self.names:
            raise ConditionError(f"unknown selection {tok!r}")
        return ("name", tok)


def parse_condition(text: str, names: list[str]):
    if not text or not text.strip():
        raise ConditionError("empty condition")
    return _Parser(_tokenize(text), names).parse()


def evaluate(node, results: Mapping[str, Callable[[], bool]]) -> bool:
    kind = node[0]
    if kind == "name":
        return results[node[1]]()
    if kind == "not":
        return not evaluate(node[1], results)
    if kind == "and":
        return evaluate(node[1], results) and evaluate(node[2], results)
    if kind == "or":
        return evaluate(node[1], results) or evaluate(node[2], results)
    _, n, names = node  # quantifier; n None means "all"
    hits = sum(1 for nm in names if results[nm]())
    return hits == len(names) if n is None else hits >= n
