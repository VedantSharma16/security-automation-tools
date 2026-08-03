"""Scanning git history (not just the working tree) for leaked secrets.

A secret that was committed and later "removed" in a follow-up commit is
still sitting in every clone's ``.git`` history — rotating the credential,
not scrubbing history, is the actual fix, but plenty of leaks are never
caught in the first place because a plain working-tree grep only ever sees
the *current* file contents. This module walks the commit history's diffs
(added lines only, since a removed secret is still a leak the moment it's
added) and runs the same rule set over them.

Implementation note: this shells out to the system ``git`` binary rather
than adding a GitPython dependency, since it's the one operation (`git log
-p --unified=0`) that already gives us everything needed: which commit,
which file, which line, and only the *added* side of each hunk.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .allowlist import Allowlist
from .scanner import Finding, scan_text
from .rules import DEFAULT_RULES

COMMIT_MARKER = "\x01"
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitError(RuntimeError):
    """Raised when the target path isn't a usable git repository."""


def _run_git(args: list, repo_path: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found on PATH") from exc

    if result.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _is_git_repo(repo_path: Path) -> bool:
    try:
        _run_git(["rev-parse", "--git-dir"], repo_path)
        return True
    except GitError:
        return False


def _iter_added_lines(log_output: str):
    """Yield (commit, file_path, line_number, added_line_text) tuples."""
    commit = None
    current_file = None
    new_line_no = None

    for raw_line in log_output.split("\n"):
        if raw_line.startswith(COMMIT_MARKER):
            commit = raw_line[len(COMMIT_MARKER):].strip()
            current_file = None
            new_line_no = None
            continue

        if raw_line.startswith("+++ "):
            path = raw_line[4:].strip()
            current_file = None if path == "/dev/null" else re.sub(r"^b/", "", path)
            continue

        hunk_match = _HUNK_HEADER.match(raw_line)
        if hunk_match:
            new_line_no = int(hunk_match.group(1))
            continue

        if raw_line.startswith("+") and current_file is not None and new_line_no is not None:
            yield commit, current_file, new_line_no, raw_line[1:]
            new_line_no += 1


def scan_git_history(
    repo_path,
    *,
    rules=DEFAULT_RULES,
    use_entropy: bool = True,
    allowlist: Allowlist | None = None,
    all_branches: bool = True,
    max_commits: int | None = None,
) -> list:
    """Scan every added line across the repo's commit history for secrets.

    Findings carry ``source="git-history"`` and the short commit SHA they
    were introduced in, so a hit can be worked backwards to "rotate this
    credential and consider it burned" even if it's absent from HEAD.
    """
    repo_path = Path(repo_path).resolve()
    if not _is_git_repo(repo_path):
        raise GitError(f"{repo_path} is not a git repository")

    log_args = [
        "log",
        "--no-color",
        "-p",
        "--unified=0",
        f"--pretty=format:{COMMIT_MARKER}%H",
    ]
    if all_branches:
        log_args.insert(1, "--all")
    if max_commits:
        log_args.append(f"-{max_commits}")

    log_output = _run_git(log_args, repo_path)

    # Group added lines by (commit, file) so each file's added lines within
    # a commit are scanned together as one text blob -- this keeps the
    # multi-line-context assumptions in scan_text (e.g. adjacent lines
    # belonging to the same statement) meaningful instead of scanning one
    # isolated line at a time.
    grouped: dict = {}
    for commit, file_path, line_no, text in _iter_added_lines(log_output):
        grouped.setdefault((commit, file_path), []).append((line_no, text))

    findings: list = []
    for (commit, file_path), lines in grouped.items():
        lines.sort(key=lambda pair: pair[0])
        blob = "\n".join(text for _, text in lines)
        file_findings = scan_text(
            blob,
            file_label=file_path,
            rules=rules,
            use_entropy=use_entropy,
            source="git-history",
            commit=commit[:12] if commit else None,
            allowlist=allowlist,
        )
        # Remap scan_text's 1-based-within-blob line numbers back to the
        # actual line numbers in that version of the file.
        for f in file_findings:
            real_line = lines[f.line_number - 1][0]
            findings.append(
                Finding(
                    file=f.file,
                    line_number=real_line,
                    rule_id=f.rule_id,
                    severity=f.severity,
                    description=f.description,
                    redacted_secret=f.redacted_secret,
                    line_preview=f.line_preview,
                    source=f.source,
                    commit=f.commit,
                )
            )
    return findings
