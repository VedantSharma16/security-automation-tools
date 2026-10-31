"""Parser/evaluator for Sigma condition expressions.

Grammar (lowest to highest precedence):
    expr    := term ('or' term)*
    term    := factor ('and' factor)*
    factor  := 'not' factor | '(' expr ')' | quant | NAME
    quant   := ('1'|'all') 'of' (NAME_GLOB | 'them')
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")
KEYWORDS = {"and", "or", "not", "of"}


class ConditionError(ValueError):
    pass


@dataclass
class Name:
    name: str


@dataclass
class Not:
    child: object


@dataclass
class BoolOp:
    op: str  # "and" | "or"
    children: list


@dataclass
class Quant:
    mode: str  # "1" | "all"
    pattern: str


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text)


class _Parser:
    def __init__(self, tokens: list[str]):
        self.t = tokens
        self.i = 0

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def next(self):
        if self.i >= len(self.t):
            raise ConditionError("unexpected end of condition")
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        node = self.expr()
        if self.i != len(self.t):
            raise ConditionError(f"unexpected token {self.t[self.i]!r}")
        return node

    def expr(self):
        kids = [self.term()]
        while self.peek() == "or":
            self.next()
            kids.append(self.term())
        return kids[0] if len(kids) == 1 else BoolOp("or", kids)

    def term(self):
        kids = [self.factor()]
        while self.peek() == "and":
            self.next()
            kids.append(self.factor())
        return kids[0] if len(kids) == 1 else BoolOp("and", kids)

    def factor(self):
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        if tok == "not":
            self.next()
            return Not(self.factor())
        if tok == "(":
            self.next()
            node = self.expr()
            if self.peek() != ")":
                raise ConditionError("missing closing parenthesis")
            self.next()
            return node
        if tok in ("1", "all") and self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            mode = self.next().lower()
            self.next()  # of
            return Quant(mode, self.next())
        if tok in KEYWORDS or tok == ")":
            raise ConditionError(f"unexpected token {self.t[self.i]!r}")
        return Name(self.next())


def parse_condition(text: str):
    return _Parser(tokenize(text)).parse()


def referenced_names(node) -> set[str]:
    if isinstance(node, Name):
        return {node.name}
    if isinstance(node, Not):
        return referenced_names(node.child)
    if isinstance(node, BoolOp):
        return set().union(*(referenced_names(c) for c in node.children))
    return set()


def evaluate(node, results: dict[str, bool]) -> bool:
    """Evaluate a parsed condition given {selection_name: bool}."""
    if isinstance(node, Name):
        if node.name not in results:
            raise ConditionError(f"unknown selection {node.name!r}")
        return results[node.name]
    if isinstance(node, Not):
        return not evaluate(node.child, results)
    if isinstance(node, BoolOp):
        fn = all if node.op == "and" else any
        return fn(evaluate(c, results) for c in node.children)
    if isinstance(node, Quant):
        if node.pattern.lower() == "them":
            vals = list(results.values())
        else:
            vals = [v for k, v in results.items() if fnmatch.fnmatchcase(k, node.pattern)]
        if not vals:
            raise ConditionError(f"pattern {node.pattern!r} matches no selections")
        return all(vals) if node.mode == "all" else any(vals)
    raise ConditionError(f"bad node {node!r}")
