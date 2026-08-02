"""Walking a working tree and scanning files for secrets.

Findings never carry the raw secret value in memory once created: each match
is immediately redacted (``redact``) and reduced to a stable ``fingerprint``
(a hash of the file, rule, and matched text) used for baseline suppression.
This keeps the scanner's own output -- console, JSON reports, baseline files
-- safe to paste into a ticket or commit to a repo without re-leaking the
secret it found.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from .entropy import DEFAULT_MIN_ENTROPY, DEFAULT_MIN_LENGTH, find_entropy_secrets
from .rules import Rule

DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "env",
        "__pycache__",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "target",
        ".idea",
        ".vscode",
        "vendor",
    }
)

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MiB; larger files are almost never source.


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    category: str
    description: str
    detector: str  # "rule" or "entropy"
    file_path: str
    line_number: int
    preview: str
    fingerprint: str
    commit: str | None = None
    author: str | None = None
    date: str | None = None


def redact(secret: str) -> str:
    """Mask a secret for display, keeping only a few boundary characters."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"


def make_fingerprint(file_path: str, rule_id: str, secret: str) -> str:
    """A stable identifier for a (file, rule, secret) triple, used for baselining.

    Based on the raw matched text so it survives line-number churn, but the
    raw text itself is never stored on the Finding -- only this hash and the
    redacted preview are.
    """
    digest = hashlib.sha256(f"{file_path}:{rule_id}:{secret}".encode("utf-8", "replace"))
    return digest.hexdigest()[:16]


def is_probably_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def iter_files(root: Path, exclude_dirs: frozenset = DEFAULT_EXCLUDE_DIRS):
    """Yield scannable file paths under ``root``, pruning excluded dirs and
    skipping binaries/oversized files."""
    if root.is_file():
        yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs and not d.startswith(".git")]
        for filename in filenames:
            path = Path(dirpath) / filename
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
                with open(path, "rb") as fh:
                    if is_probably_binary(fh.read(8000)):
                        continue
            except OSError:
                continue
            yield path


def scan_lines(
    lines,
    file_path: str,
    rules: list,
    enable_entropy: bool = True,
    min_entropy: float = DEFAULT_MIN_ENTROPY,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> list:
    """Scan an iterable of (1-indexed line_number, text) pairs for secrets."""
    findings = []
    for line_number, line in lines:
        for rule in rules:
            match = rule.search(line)
            if match is None:
                continue
            secret = match.group(0)
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    detector="rule",
                    file_path=file_path,
                    line_number=line_number,
                    preview=redact(secret),
                    fingerprint=make_fingerprint(file_path, rule.id, secret),
                )
            )

        if enable_entropy:
            for hit in find_entropy_secrets(line, min_entropy=min_entropy, min_length=min_length):
                rule_id = "generic-high-entropy-secret"
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity="low",
                        category="generic",
                        description=(
                            f"High-entropy value ({hit.entropy:.2f} bits/char) assigned to "
                            f"suspicious key '{hit.key}'."
                        ),
                        detector="entropy",
                        file_path=file_path,
                        line_number=line_number,
                        preview=redact(hit.value),
                        fingerprint=make_fingerprint(file_path, rule_id, hit.value),
                    )
                )
    return findings


def scan_file(
    path: Path,
    rules: list,
    root: Path,
    enable_entropy: bool = True,
    min_entropy: float = DEFAULT_MIN_ENTROPY,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> list:
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, OSError):
        return []

    try:
        rel_path = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        rel_path = path.as_posix()

    lines = enumerate(text.splitlines(), start=1)
    return scan_lines(lines, rel_path, rules, enable_entropy, min_entropy, min_length)


def scan_paths(
    paths: list,
    rules: list,
    enable_entropy: bool = True,
    exclude_dirs: frozenset = DEFAULT_EXCLUDE_DIRS,
    min_entropy: float = DEFAULT_MIN_ENTROPY,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> list:
    """Scan a list of file/directory paths, returning all findings."""
    findings = []
    for raw_path in paths:
        path = Path(raw_path)
        root = path if path.is_dir() else path.parent
        for file_path in iter_files(path, exclude_dirs):
            findings.extend(
                scan_file(file_path, rules, root, enable_entropy, min_entropy, min_length)
            )
    return findings
