"""Scanning git history for secrets that were ever committed.

A secret removed from the working tree (`git rm`, edited out, `.gitignore`d
after the fact) is still sitting in every commit that introduced it -- it's
recoverable with a plain `git show` for as long as the repo exists. Rotating
the credential is the only real fix; the working-tree scan in
:mod:`secretscan.scanner` can't see it at all. This module runs the same
rule/entropy detectors from :mod:`secretscan.scanner` over every line ever
*added* in the repo's commit history by parsing ``git log -p``.
"""

from __future__ import annotations

import dataclasses
import re
import subprocess
from pathlib import Path

from .entropy import DEFAULT_MIN_ENTROPY, DEFAULT_MIN_LENGTH
from .scanner import scan_lines

_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitScanError(RuntimeError):
    """Raised when git history can't be read (not a repo, git missing, etc.)."""


def _run_git_log(repo_path: Path, max_commits: int = None, all_branches: bool = False) -> str:
    cmd = ["git", "-C", str(repo_path), "log", "-p", "--no-color", "--unified=0", "--no-renames"]
    if all_branches:
        cmd.append("--all")
    if max_commits:
        cmd += ["-n", str(max_commits)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError as exc:
        raise GitScanError("git is not installed or not on PATH") from exc

    if result.returncode != 0:
        raise GitScanError(f"git log failed: {result.stderr.strip()}")
    return result.stdout


def parse_added_lines(patch_text: str):
    """Yield one dict per line added anywhere in the patch stream.

    Each dict has: commit, author, date, file, line_number, text. Only
    ``+`` lines advance the new-file line counter; ``-`` lines (removed
    content) don't appear in the new file at all, so they're skipped for
    the purposes of this scan.
    """
    commit = author = date = current_file = None
    new_line_no = None

    for line in patch_text.splitlines():
        if line.startswith("commit "):
            commit = line.split(maxsplit=1)[1][:12]
            author = date = current_file = None
        elif line.startswith("Author:"):
            author = line[len("Author:") :].strip()
        elif line.startswith("Date:"):
            date = line[len("Date:") :].strip()
        elif line.startswith("+++ "):
            path = line[4:].strip()
            current_file = None if path == "/dev/null" else path.removeprefix("b/")
        elif line.startswith("@@"):
            m = _HUNK_HEADER.match(line)
            new_line_no = int(m.group(1)) if m else None
        elif line.startswith("+") and not line.startswith("+++"):
            if current_file is not None and new_line_no is not None:
                yield {
                    "commit": commit,
                    "author": author,
                    "date": date,
                    "file": current_file,
                    "line_number": new_line_no,
                    "text": line[1:],
                }
                new_line_no += 1
        # '-' (removed) and unmatched context lines don't advance new_line_no.


def scan_git_history(
    repo_path,
    rules: list,
    enable_entropy: bool = True,
    max_commits: int = None,
    all_branches: bool = False,
    min_entropy: float = DEFAULT_MIN_ENTROPY,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> list:
    """Scan every line ever added in ``repo_path``'s commit history."""
    patch_text = _run_git_log(Path(repo_path), max_commits, all_branches)

    findings = []
    for entry in parse_added_lines(patch_text):
        line_findings = scan_lines(
            [(entry["line_number"], entry["text"])],
            entry["file"],
            rules,
            enable_entropy,
            min_entropy,
            min_length,
        )
        for finding in line_findings:
            findings.append(
                dataclasses.replace(
                    finding, commit=entry["commit"], author=entry["author"], date=entry["date"]
                )
            )
    return findings
