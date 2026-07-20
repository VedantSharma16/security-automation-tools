"""Filesystem walking and per-line rule evaluation."""

from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .rules import Rule

# Directories that are never worth scanning: VCS internals, dependency
# trees, virtualenvs, and build output. These are excluded by name at any
# depth, not just at the scan root.
DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "venv",
        ".venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        "dist",
        "build",
        ".egg-info",
    }
)

# Skip files above this size — large binaries/data dumps aren't source
# files worth scanning line-by-line, and reading them wastes time.
DEFAULT_MAX_FILE_SIZE = 5_000_000

_BINARY_PROBE_BYTES = 8192


@dataclass(frozen=True)
class Finding:
    file: str
    line_number: int
    rule: Rule
    secret: str
    line_text: str

    def fingerprint(self) -> str:
        """Stable identity for baseline diffing, independent of file order."""
        digest = hashlib.sha256(f"{self.file}:{self.rule.id}:{self.secret}".encode("utf-8"))
        return digest.hexdigest()

    def redacted_secret(self) -> str:
        """Show just enough of a matched secret to identify it without
        leaking the whole value into logs, reports, or CI output."""
        if len(self.secret) <= 8:
            return "*" * len(self.secret)
        return f"{self.secret[:4]}{'*' * (len(self.secret) - 8)}{self.secret[-4:]}"


def is_binary(path: Path) -> bool:
    """Heuristic: a NUL byte in the first chunk means it's not text."""
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(_BINARY_PROBE_BYTES)
    except OSError:
        return True
    return b"\x00" in chunk


def _is_excluded(rel_path: Path, exclude_globs) -> bool:
    posix = rel_path.as_posix()
    return any(fnmatch.fnmatch(posix, pattern) for pattern in exclude_globs)


def iter_text_files(root: Path, exclude_globs=(), max_file_size: int = DEFAULT_MAX_FILE_SIZE):
    """Yield scannable text file paths under `root`, depth-first.

    Skips VCS/dependency/build directories, oversized files, and anything
    that looks binary, and honors caller-supplied exclude glob patterns
    matched against the path relative to `root`.
    """
    root = Path(root)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in DEFAULT_EXCLUDE_DIRS for part in rel.parts[:-1]):
            continue
        if exclude_globs and _is_excluded(rel, exclude_globs):
            continue
        try:
            if path.stat().st_size > max_file_size:
                continue
        except OSError:
            continue
        if is_binary(path):
            continue
        yield path


def _dedupe_line_findings(line_findings: list) -> list:
    """Drop generic-entropy findings that duplicate a specific signature hit.

    A line like `STRIPE_SECRET_KEY = "sk_live_..."` trips both the
    dedicated Stripe rule and the generic `*_secret_key = <high-entropy>`
    rule. The specific rule is strictly more informative, so once a secret
    string has been matched by any non-generic rule on a line, drop the
    generic-category match for that same secret rather than reporting it
    twice.
    """
    specific_secrets = {f.secret for f in line_findings if f.rule.category != "Generic"}
    return [
        f
        for f in line_findings
        if f.rule.category != "Generic" or f.secret not in specific_secrets
    ]


def scan_file(path: Path, root: Path, rules: list) -> list:
    """Scan a single file against every rule, line by line."""
    findings = []
    rel_path = path.relative_to(root).as_posix()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line_number, line in enumerate(fh, start=1):
                line_findings = []
                for rule in rules:
                    for _start, _end, secret in rule.find_secrets(line):
                        line_findings.append(
                            Finding(
                                file=rel_path,
                                line_number=line_number,
                                rule=rule,
                                secret=secret,
                                line_text=line.rstrip("\n"),
                            )
                        )
                findings.extend(_dedupe_line_findings(line_findings))
    except OSError:
        return []
    return findings


def scan_path(root, rules: list, exclude_globs=()) -> tuple:
    """Scan every text file under `root`.

    Returns (findings, files_scanned) — findings sorted by file path and
    line number, files_scanned counting every file actually read (after
    exclusions), for reporting scan coverage.
    """
    root = Path(root)
    findings = []
    files_scanned = 0
    for path in iter_text_files(root, exclude_globs=exclude_globs):
        files_scanned += 1
        findings.extend(scan_file(path, root, rules))
    findings.sort(key=lambda f: (f.file, f.line_number, f.rule.id))
    return findings, files_scanned
