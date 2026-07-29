"""Scanning git history for secrets that were committed and later removed.

A secret deleted in a later commit is still sitting in every earlier commit
that ever contained it — anyone with clone access can `git log -p` or
`git show` their way to it. Working-tree scanning (``scanner.py``) can never
find that, so this module runs the same signature/entropy detectors against
every line ever *added* across the repository's history via ``git log -p``.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .patterns import Signature
from .scanner import Finding, scan_line

_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_DIFF_GIT_RE = re.compile(r"^diff --git a/(.*) b/(.*)$")


@dataclass(frozen=True)
class GitAddedLine:
    commit: str
    author: str
    date: str
    file: str
    line_number: int
    text: str


class GitScanError(RuntimeError):
    """Raised when ``git log`` cannot be run against the target path."""


def run_git_log(repo_path: str | Path, max_commits: int | None = None) -> str:
    """Return the raw ``git log -p`` output for the repo at ``repo_path``."""
    cmd = ["git", "-C", str(repo_path), "log", "-p", "--no-color", "-U0"]
    if max_commits:
        cmd += ["-n", str(max_commits)]

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise GitScanError(result.stderr.strip() or "git log failed")
    return result.stdout


def parse_git_log(log_text: str) -> list[GitAddedLine]:
    """Parse ``git log -p -U0`` output into every line that was ever added."""
    added: list[GitAddedLine] = []

    commit = author = date = current_file = ""
    new_line = 0

    for raw_line in log_text.splitlines():
        if raw_line.startswith("commit "):
            commit = raw_line.split()[1]
            author = date = ""
            continue
        if raw_line.startswith("Author: "):
            author = raw_line[len("Author: "):].strip()
            continue
        if raw_line.startswith("Date: "):
            date = raw_line[len("Date: "):].strip()
            continue

        diff_match = _DIFF_GIT_RE.match(raw_line)
        if diff_match:
            current_file = diff_match.group(2)
            continue

        hunk_match = _HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            new_line = int(hunk_match.group(1))
            continue

        if raw_line.startswith("+++") or raw_line.startswith("---"):
            continue

        if raw_line.startswith("+"):
            added.append(
                GitAddedLine(
                    commit=commit,
                    author=author,
                    date=date,
                    file=current_file,
                    line_number=new_line,
                    text=raw_line[1:],
                )
            )
            new_line += 1
        # removed ("-") and other diff metadata lines don't advance new_line

    return added


def scan_git_history(
    repo_path: str | Path,
    signatures: list[Signature],
    max_commits: int | None = None,
    entropy_threshold: float = 3.5,
    min_length: int = 12,
) -> list[Finding]:
    """Scan every added line across the repo's commit history for secrets."""
    log_text = run_git_log(repo_path, max_commits=max_commits)
    findings = []
    for added in parse_git_log(log_text):
        for hit in scan_line(added.text, signatures, entropy_threshold, min_length):
            findings.append(
                Finding(
                    file=added.file,
                    line_number=added.line_number,
                    commit=added.commit[:12],
                    **hit,
                )
            )
    return findings
