"""Scanning engines: current working tree and full git history.

Both engines funnel through the same `_scan_line` helper so a secret is
detected identically regardless of where it was found - only how the
(file, line, commit) coordinates are produced differs.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess

from .models import Finding
from .rules import RULES, find_generic_secrets

DEFAULT_EXCLUDE_DIRS = {
    ".git",
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
    "site-packages",
    ".idea",
    ".vscode",
}

MAX_FILE_BYTES = 2_000_000


def redact(value: str) -> str:
    """Show just enough of a secret to identify it without leaking it."""
    if len(value) <= 8:
        return value[:2] + "…" if len(value) > 2 else "…"
    return f"{value[:4]}…{value[-4:]}"


def fingerprint(rule_id: str, file: str, value: str) -> str:
    """Stable identifier for a (rule, location, value) triple.

    Used by the baseline to suppress a known/accepted finding across
    reruns even if surrounding lines shift.
    """
    digest = hashlib.sha256(f"{rule_id}:{file}:{value}".encode("utf-8")).hexdigest()
    return digest[:16]


def _scan_line(line: str, min_entropy: float):
    """Return (rule_id, description, severity, raw_value) tuples found in a line."""
    hits = []
    for rule in RULES:
        match = rule.pattern.search(line)
        if match:
            value = match.group(rule.group) if rule.group else match.group(0)
            hits.append((rule.rule_id, rule.description, rule.severity, value))
    if not hits:
        # Only fall back to the entropy heuristic when no precise
        # vendor-format rule already explains this line.
        for value, _span in find_generic_secrets(line, min_entropy=min_entropy):
            hits.append(
                ("generic-high-entropy-secret", "Generic high-entropy secret assignment", "MEDIUM", value)
            )
    return hits


def _is_binary(chunk: bytes) -> bool:
    return b"\0" in chunk


def discover_files(root: str, extra_excludes: set[str] | None = None):
    """Yield text file paths under `root`, skipping vendor dirs and binaries."""
    excludes = DEFAULT_EXCLUDE_DIRS | (extra_excludes or set())
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in excludes]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
                with open(path, "rb") as fh:
                    chunk = fh.read(4096)
                if _is_binary(chunk):
                    continue
            except OSError:
                continue
            yield path


def scan_file(path: str, root: str, min_entropy: float = 3.5) -> list[Finding]:
    findings: list[Finding] = []
    rel = os.path.relpath(path, root)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                for rule_id, description, severity, value in _scan_line(line, min_entropy):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            description=description,
                            severity=severity,
                            file=rel,
                            line=lineno,
                            redacted=redact(value),
                            fingerprint=fingerprint(rule_id, rel, value),
                            commit=None,
                        )
                    )
    except OSError:
        pass
    return findings


def scan_working_tree(
    root: str, min_entropy: float = 3.5, extra_excludes: set[str] | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    for path in discover_files(root, extra_excludes=extra_excludes):
        findings.extend(scan_file(path, root, min_entropy=min_entropy))
    return findings


# --- git history scanning ------------------------------------------------

_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _run_git(repo_root: str, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", repo_root, *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _list_commits(repo_root: str, max_commits: int | None = None) -> list[str]:
    out = _run_git(repo_root, "log", "--all", "--pretty=format:%H")
    commits = [c for c in out.splitlines() if c]
    if max_commits is not None:
        commits = commits[:max_commits]
    return commits


def _iter_added_lines(diff_text: str):
    """Yield (file_path, line_number, line_content) for every '+' line in a
    `--unified=0` diff. Assumes no context lines, so the new-file line
    counter only needs to track hunk headers and other added lines."""
    current_file = None
    new_lineno = None
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:]
            current_file = None if path == "/dev/null" else path[2:]  # strip "b/"
            continue
        header = _HUNK_HEADER.match(raw)
        if header:
            new_lineno = int(header.group(1))
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("+"):
            if current_file is not None and new_lineno is not None:
                yield current_file, new_lineno, raw[1:]
                new_lineno += 1
        # '-' lines don't consume the new-file line counter; anything else
        # (diff --git, index, binary-file notices) is metadata we skip.


def scan_git_history(
    repo_root: str, min_entropy: float = 3.5, max_commits: int | None = None
) -> list[Finding]:
    """Scan every commit's added lines for secrets - including ones later
    deleted from the working tree, which a plain file scan would miss."""
    findings: list[Finding] = []
    try:
        commits = _list_commits(repo_root, max_commits=max_commits)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return findings

    for commit in commits:
        try:
            diff_text = _run_git(
                repo_root, "show", "--unified=0", "--format=", "--no-color", commit
            )
        except subprocess.CalledProcessError:
            continue
        for file_path, lineno, content in _iter_added_lines(diff_text):
            for rule_id, description, severity, value in _scan_line(content, min_entropy):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        description=description,
                        severity=severity,
                        file=file_path,
                        line=lineno,
                        redacted=redact(value),
                        fingerprint=fingerprint(rule_id, file_path, value),
                        commit=commit[:12],
                    )
                )
    return findings
