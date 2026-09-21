"""Scanning the current working tree (as opposed to git history) for secrets."""

from __future__ import annotations

from pathlib import Path

from .finding import Finding, make_fingerprint
from .linehelpers import (
    BINARY_EXTENSIONS,
    DEFAULT_IGNORE_DIRS,
    extract_context_key,
    looks_binary,
)
from .redact import redact

MAX_FILE_SIZE = 5_000_000  # 5 MB; larger files are almost never source/config


def iter_scannable_files(root: Path, ignore_dirs=DEFAULT_IGNORE_DIRS):
    """Yield every file under ``root`` worth scanning as text."""
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in ignore_dirs for part in path.relative_to(root).parts[:-1]):
            continue
        if path.suffix.lower() in BINARY_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE or path.stat().st_size == 0:
                continue
            with open(path, "rb") as fh:
                sample = fh.read(8192)
        except OSError:
            continue
        if looks_binary(sample):
            continue
        yield path


def scan_file(path: Path, rules: list, root: Path) -> list:
    """Scan a single file's lines against every rule, returning Findings."""
    findings = []
    rel_path = path.relative_to(root).as_posix()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return findings

    for line_no, line in enumerate(lines, start=1):
        for rule in rules:
            for match in rule.find_all(line):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        file_path=rel_path,
                        line=line_no,
                        context_key=extract_context_key(line),
                        redacted=redact(match.secret_text),
                        fingerprint=make_fingerprint(rule.id, rel_path, match.secret_text),
                        source="working-tree",
                    )
                )
    return findings


def scan_working_tree(root: Path, rules: list) -> list:
    """Scan every scannable file under ``root``, returning all Findings."""
    findings = []
    for path in iter_scannable_files(root):
        findings.extend(scan_file(path, rules, root))
    return findings
