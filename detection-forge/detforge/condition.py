"""Parser/evaluator for Sigma-style condition expressions.

Grammar (precedence: not > and > or):
    expr   := term ('or' term)*
    term   := factor ('and' factor)*
    factor := 'not' factor | '(' expr ')' | quant | NAME
    quant  := ('1'|'all') 'of' (NAME-with-optional-* | 'them')
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Callable, Iterable


class ConditionError(ValueError):
    pass


_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")
_KEYWORDS = {"and", "or", "not", "of", "them"}


def tokenize(text: str) -> list[str]:
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"unexpected character at {pos}: {text[pos:pos+10]!r}")
        out.append(m.group(1))
        pos = m.end()
    if not out:
        raise ConditionError("empty condition")
    return out


@dataclass
class Node:
    kind: str  # name | not | and | or | quant
    value: object = None
    children: tuple = ()


class _Parser:
    def __init__(self, tokens: list[str]):
        self.t, self.i = tokens, 0

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self) -> Node:
        node = self.expr()
        if self.i != len(self.t):
            raise ConditionError(f"unexpected token {self.t[self.i]!r}")
        return node

    def expr(self) -> Node:
        node = self.term()
        while self.peek() == "or":
            self.take()
            node = Node("or", children=(node, self.term()))
        return node

    def term(self) -> Node:
        node = self.factor()
        while self.peek() == "and":
            self.take()
            node = Node("and", children=(node, self.factor()))
        return node

    def factor(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        if tok == "not":
            self.take()
            return Node("not", children=(self.factor(),))
        if tok == "(":
            self.take()
            node = self.expr()
            if self.peek() != ")":
                raise ConditionError("missing closing parenthesis")
            self.take()
            return node
        if tok in ("1", "all") and self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            self.take(), self.take()
            if self.peek() is None:
                raise ConditionError("'of' needs a target")
            pattern = self.take()
            return Node("quant", value=(tok, pattern.lower() if pattern.lower() == "them" else pattern))
        if tok in _KEYWORDS or tok == ")":
            raise ConditionError(f"unexpected token {tok!r}")
        return Node("name", value=self.take())


def parse(text: str) -> Node:
    return _Parser(tokenize(text)).parse()


def referenced_names(node: Node, all_names: Iterable[str]) -> set[str]:
    all_names = list(all_names)
    if node.kind == "name":
        return {node.value}
    if node.kind == "quant":
        pat = node.value[1]
        return set(all_names) if pat == "them" else set(fnmatch.filter(all_names, pat))
    out: set[str] = set()
    for c in node.children:
        out |= referenced_names(c, all_names)
    return out


def evaluate(node: Node, lookup: Callable[[str], bool], names: Iterable[str]) -> bool:
    names = list(names)
    k = node.kind
    if k == "name":
        return lookup(node.value)
    if k == "not":
        return not evaluate(node.children[0], lookup, names)
    if k == "and":
        return all(evaluate(c, lookup, names) for c in node.children)
    if k == "or":
        return any(evaluate(c, lookup, names) for c in node.children)
    mode, pat = node.value
    pool = names if pat == "them" else fnmatch.filter(names, pat)
    if not pool:
        return False
    results = (lookup(n) for n in pool)
    return any(results) if mode == "1" else all(results)
