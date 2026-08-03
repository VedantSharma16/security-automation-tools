"""Suppressing known false positives.

Two layers, applied in order:

1. A small built-in set of common placeholder values (``changeme``,
   ``your-api-key-here``, ...) is always suppressed -- no secret scanner is
   useful if every README's example config trips it.
2. An optional ``.secretsallowlist`` file lets a repo suppress its own
   known false positives by path glob, rule id, matched-text regex, or exact
   literal value (e.g. an intentionally-fake secret in a test fixture).

The allowlist file is plain text rather than YAML/JSON so the core package
has zero required dependencies:

    # comment
    path:tests/fixtures/**
    rule:jwt
    regex:^AKIAFAKEEXAMPLE
    literal:hunter2
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PLACEHOLDER_VALUES = frozenset(
    v.lower()
    for v in (
        "changeme",
        "change_me",
        "change-me",
        "your-api-key-here",
        "your_api_key_here",
        "youraccesskeyhere",
        "yoursecrethere",
        "password",
        "password123",
        "123456",
        "hunter2",
        "placeholder",
        "example",
        "redacted",
        "notarealsecret",
        "not-a-real-secret",
        "fakekey",
        "fake-key",
        "dummy",
        "dummysecret",
        "test",
        "testing",
        "xxxxxxxx",
        "insertyourkeyhere",
    )
)


@dataclass
class Allowlist:
    path_globs: tuple = ()
    rule_ids: frozenset = field(default_factory=frozenset)
    regexes: tuple = ()
    literals: frozenset = field(default_factory=frozenset)

    def is_allowed(self, *, file_path: str, rule_id: str, matched_text: str) -> bool:
        stripped = matched_text.strip().strip("'\"")
        if stripped.lower() in DEFAULT_PLACEHOLDER_VALUES:
            return True
        if stripped.lower() in self.literals:
            return True
        if rule_id in self.rule_ids:
            return True
        normalized = file_path.replace("\\", "/")
        for pattern in self.path_globs:
            if fnmatch.fnmatch(normalized, pattern):
                return True
        for pattern in self.regexes:
            if pattern.search(matched_text):
                return True
        return False


def load(path) -> Allowlist:
    """Parse a ``.secretsallowlist`` file into an :class:`Allowlist`.

    A missing path yields an allowlist with only the built-in placeholder
    suppressions active.
    """
    path_globs: list = []
    rule_ids: set = set()
    regexes: list = []
    literals: set = set()

    if path is None:
        return Allowlist()

    file_path = Path(path)
    if not file_path.exists():
        return Allowlist()

    for lineno, raw_line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(
                f"{file_path}:{lineno}: expected 'kind:value' (e.g. 'rule:jwt'), got {raw_line!r}"
            )
        kind, _, value = line.partition(":")
        kind = kind.strip().lower()
        value = value.strip()
        if kind == "path":
            path_globs.append(value)
        elif kind == "rule":
            rule_ids.add(value)
        elif kind == "regex":
            regexes.append(re.compile(value))
        elif kind == "literal":
            literals.add(value.lower())
        else:
            raise ValueError(
                f"{file_path}:{lineno}: unknown allowlist entry kind {kind!r}; "
                "expected one of: path, rule, regex, literal"
            )

    return Allowlist(
        path_globs=tuple(path_globs),
        rule_ids=frozenset(rule_ids),
        regexes=tuple(regexes),
        literals=frozenset(literals),
    )
