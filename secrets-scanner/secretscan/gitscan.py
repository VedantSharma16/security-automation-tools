"""Scanning git history for secrets that were committed and later removed.

A secret that only ever lived in the working tree is gone the moment someone
deletes it. A secret that was ever *committed* lives forever in git history
(every clone has it) unless the history itself is rewritten — which is why a
useful secrets scanner has to walk commits, not just the checked-out files.

This module shells out to the ``git`` CLI rather than depending on a
third-party git library, and parses unified diffs (``git log -p
--unified=0``) itself. That keeps the tool dependency-free, at the cost of a
couple of documented edge cases (see README) around merge commits and
filenames containing spaces.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .finding import Finding, make_fingerprint
from .linehelpers import extract_context_key
from .redact import redact

_COMMIT_MARKER = "\x01COMMIT\x01"
_DIFF_GIT_RE = re.compile(r"^diff --git a/.* b/(.*)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitCommandError(RuntimeError):
    """Raised when the underlying `git` invocation fails."""


def is_git_repo(path: Path) -> bool:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def _run_git_log(path: Path) -> str:
    cmd = [
        "git", "-C", str(path), "log", "--all", "--no-color", "--unified=0",
        f"--format={_COMMIT_MARKER}%H\x01%an\x01%aI", "-p", "--",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if result.returncode != 0:
        raise GitCommandError(result.stderr.strip() or "git log failed")
    return result.stdout


def iter_added_lines(path: Path):
    """Yield ``(commit_sha, author, date, file_path, line_no, text)`` for every
    line *added* anywhere in the repo's history, across all refs.

    Only added ("+") lines are yielded — a secret that was only ever removed
    isn't a leak introduced by this repo's history. Binary diffs and merge
    commits (which `git log -p` shows no diff for by default) are skipped
    automatically because they never reach the ``BODY`` state below.
    """
    output = _run_git_log(path)
    if not output:
        return

    commit_sha = author = date = None
    current_file = None
    state = "OUTSIDE"  # OUTSIDE -> FILEHEADER (saw "diff --git") -> BODY (saw "+++")
    line_no = None

    for raw_line in output.split("\n"):
        if raw_line.startswith(_COMMIT_MARKER):
            commit_sha, author, date = raw_line[len(_COMMIT_MARKER):].split("\x01", 2)
            current_file = None
            state = "OUTSIDE"
            continue

        diff_match = _DIFF_GIT_RE.match(raw_line)
        if diff_match:
            current_file = diff_match.group(1)
            state = "FILEHEADER"
            line_no = None
            continue

        if state == "FILEHEADER":
            if raw_line.startswith("+++ "):
                state = "BODY"
            # "--- a/...", "index ...", mode-change lines: nothing to do
            continue

        if state != "BODY":
            continue

        hunk_match = _HUNK_RE.match(raw_line)
        if hunk_match:
            line_no = int(hunk_match.group(1))
            continue

        if raw_line.startswith("+") and line_no is not None:
            yield commit_sha, author, date, current_file, line_no, raw_line[1:]
            line_no += 1
        # "-" (removed) lines and "\ No newline at end of file" don't advance
        # the new-file line counter.


def scan_git_history(root: Path, rules: list) -> list:
    """Scan every line ever added across all branches, returning Findings."""
    findings = []
    for commit_sha, author, date, file_path, line_no, text in iter_added_lines(root):
        for rule in rules:
            for match in rule.find_all(text):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        file_path=file_path,
                        line=line_no,
                        context_key=extract_context_key(text),
                        redacted=redact(match.secret_text),
                        fingerprint=make_fingerprint(rule.id, file_path, match.secret_text),
                        source="git-history",
                        commit=commit_sha[:12] if commit_sha else None,
                        author=author,
                        date=date,
                    )
                )
    return findings
