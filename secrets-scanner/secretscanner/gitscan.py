"""Scan git commit history for secrets that were committed and later removed.

A secret deleted from HEAD in a follow-up commit ("oops, removing the
hardcoded key") is still fully recoverable from history via
``git show <commit>:<path>`` or `git log -p`. Working-tree scanning
(:mod:`secretscanner.scanner`) can never catch this class of leak, which is
exactly why standalone secret-scanning tools (gitleaks, trufflehog,
detect-secrets) all offer a history mode. This module re-uses the same
detectors against the *added* lines of every commit's diff.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path

from .scanner import Finding, scan_text

_COMMIT_RE = re.compile(r"^commit ([0-9a-f]{7,40})")
_AUTHOR_RE = re.compile(r"^Author:\s*(.*)$")
_DATE_RE = re.compile(r"^Date:\s*(.*)$")
_FILE_RE = re.compile(r"^\+\+\+ b/(.*)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitScanError(RuntimeError):
    """Raised when the target path isn't a usable git repository."""


@dataclass(frozen=True)
class GitFinding:
    commit: str
    author: str
    date: str
    finding: Finding


def _run_git_log(repo: Path, max_commits: int | None) -> str:
    cmd = ["git", "-C", str(repo), "log", "-p", "--unified=0", "--no-color"]
    if max_commits:
        cmd += ["-n", str(max_commits)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError as exc:  # pragma: no cover - git always present in dev/test envs
        raise GitScanError("git executable not found on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise GitScanError(f"git log failed: {exc.stderr.strip()}") from exc
    return result.stdout


def scan_git_history(repo: Path, max_commits: int | None = None) -> list[GitFinding]:
    """Scan every commit's added lines for secrets. Returns findings ordered
    newest-commit-first, matching `git log` order."""
    repo = Path(repo)
    if not (repo / ".git").is_dir():
        raise GitScanError(f"{repo} is not a git repository (no .git directory found)")

    log_text = _run_git_log(repo, max_commits)
    findings: list[GitFinding] = []

    commit = author = date = current_file = None
    next_line_no: int | None = None

    for raw_line in log_text.splitlines():
        if match := _COMMIT_RE.match(raw_line):
            commit, author, date, current_file, next_line_no = match.group(1), None, None, None, None
            continue
        if match := _AUTHOR_RE.match(raw_line):
            author = match.group(1).strip()
            continue
        if match := _DATE_RE.match(raw_line):
            date = match.group(1).strip()
            continue
        if match := _FILE_RE.match(raw_line):
            current_file = match.group(1)
            continue
        if raw_line.startswith("+++") or raw_line.startswith("---"):
            continue
        if match := _HUNK_RE.match(raw_line):
            next_line_no = int(match.group(1))
            continue
        if raw_line.startswith("+"):
            if current_file is not None and next_line_no is not None:
                content = raw_line[1:]
                for finding in scan_text(content, file_label=current_file):
                    findings.append(
                        GitFinding(
                            commit=commit or "unknown",
                            author=author or "unknown",
                            date=date or "unknown",
                            finding=replace(finding, line_number=next_line_no),
                        )
                    )
                next_line_no += 1
            continue
        # Removed ('-') and unchanged lines don't advance the new-file pointer.

    return findings
