"""Sigma condition expression parser (and/or/not, parentheses, 'N of' globs)."""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


class ConditionError(ValueError):
    pass


class Condition:
    def evaluate(self, sels: dict, event: dict) -> bool:  # pragma: no cover
        raise NotImplementedError

    def referenced_names(self) -> set[str]:
        return set()


@dataclass
class Ref(Condition):
    name: str

    def evaluate(self, sels, event):
        return sels[self.name].matches(event)

    def referenced_names(self):
        return {self.name}


@dataclass
class Quantified(Condition):
    quantifier: str  # "all" or an int as string
    pattern: str

    def _names(self, sels):
        if self.pattern == "them":
            return list(sels)
        return [n for n in sels if fnmatch.fnmatchcase(n, self.pattern)]

    def evaluate(self, sels, event):
        names = self._names(sels)
        if not names:
            return False
        hits = sum(sels[n].matches(event) for n in names)
        return hits == len(names) if self.quantifier == "all" else hits >= int(self.quantifier)

    def referenced_names(self):
        return {self.pattern} if "*" not in self.pattern and self.pattern != "them" else set()


@dataclass
class Not(Condition):
    inner: Condition

    def evaluate(self, sels, event):
        return not self.inner.evaluate(sels, event)

    def referenced_names(self):
        return self.inner.referenced_names()


@dataclass
class BoolOp(Condition):
    op: str
    parts: list

    def evaluate(self, sels, event):
        f = all if self.op == "and" else any
        return f(p.evaluate(sels, event) for p in self.parts)

    def referenced_names(self):
        return set().union(*(p.referenced_names() for p in self.parts))


def parse_condition(src: str) -> Condition:
    tokens = _TOKEN.findall(src)
    if not tokens or "".join(tokens).replace(" ", "") != re.sub(r"\s+", "", src):
        raise ConditionError(f"cannot tokenize condition: {src!r}")
    pos = 0

    def peek():
        return tokens[pos].lower() if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def p_or():
        parts = [p_and()]
        while peek() == "or":
            take()
            parts.append(p_and())
        return parts[0] if len(parts) == 1 else BoolOp("or", parts)

    def p_and():
        parts = [p_not()]
        while peek() == "and":
            take()
            parts.append(p_not())
        return parts[0] if len(parts) == 1 else BoolOp("and", parts)

    def p_not():
        if peek() == "not":
            take()
            return Not(p_not())
        return p_atom()

    def p_atom():
        t = peek()
        if t is None:
            raise ConditionError(f"unexpected end of condition: {src!r}")
        if t == "(":
            take()
            node = p_or()
            if peek() != ")":
                raise ConditionError(f"missing ')' in {src!r}")
            take()
            return node
        if t in (")", "and", "or"):
            raise ConditionError(f"unexpected {t!r} in {src!r}")
        take()
        if (t == "all" or t.isdigit()) and peek() == "of":
            take()
            if peek() is None:
                raise ConditionError(f"'{t} of' needs a selection pattern")
            return Quantified(t, take())
        return Ref(tokens[pos - 1])

    node = p_or()
    if pos != len(tokens):
        raise ConditionError(f"unexpected token {tokens[pos]!r} in {src!r}")
    return node
