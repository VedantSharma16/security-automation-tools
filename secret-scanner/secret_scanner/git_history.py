"""Git history scanning: find secrets that were committed and later removed.

A secret that's absent from the current working tree can still be sitting
in an old commit object, fully retrievable by anyone who clones the repo.
This module walks commits with `git log`/`git show` (plain subprocess calls
to the `git` binary -- no GitPython dependency) and scans only the *added*
lines of each commit's diff, so a 10,000-commit history costs one diff per
commit rather than a full checkout per commit.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .allowlist import Allowlist
from .entropy import EntropyConfig
from .findings import Finding, dedupe
from .scanner import scan_line

_LOG_FIELD_SEP = "\x1f"
_LOG_FORMAT = _LOG_FIELD_SEP.join(["%H", "%an", "%ad", "%s"])

_HUNK_HEADER_RE = None  # compiled lazily in _iter_hunks to avoid a module-level re import cycle


@dataclass(frozen=True)
class CommitMeta:
    commit_hash: str
    author: str
    date: str
    subject: str


def is_git_repo(root: "str | Path") -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


def list_commits(root: "str | Path", since: str | None = None, max_commits: int | None = None) -> list[CommitMeta]:
    args = ["git", "-C", str(root), "log", f"--format={_LOG_FORMAT}", "--date=short"]
    if max_commits:
        args += ["-n", str(max_commits)]
    args.append(f"{since}..HEAD" if since else "HEAD")

    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        return []

    commits = []
    for line in result.stdout.splitlines():
        parts = line.split(_LOG_FIELD_SEP)
        if len(parts) != 4:
            continue
        commits.append(CommitMeta(commit_hash=parts[0], author=parts[1], date=parts[2], subject=parts[3]))
    return commits


def _iter_added_lines(diff_text: str):
    """Yield (file_path, new_line_number, line_content) for every added
    line in a unified diff produced with `-U0` (zero context lines)."""
    import re

    global _HUNK_HEADER_RE
    if _HUNK_HEADER_RE is None:
        _HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    current_file = None
    next_line_no = None

    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            if path == "/dev/null":
                current_file = None
            else:
                # "b/path/to/file" -> "path/to/file"
                current_file = path.split("/", 1)[1] if path.startswith(("a/", "b/")) else path
            continue

        if raw.startswith("@@"):
            m = _HUNK_HEADER_RE.match(raw)
            if m:
                next_line_no = int(m.group(1))
            continue

        if current_file is None or next_line_no is None:
            continue

        if raw.startswith("+") and not raw.startswith("+++"):
            yield current_file, next_line_no, raw[1:]
            next_line_no += 1
        elif not raw.startswith("-"):
            next_line_no += 1


def commit_added_lines(root: "str | Path", commit_hash: str):
    """Run `git show` for one commit and yield its added lines, per-file."""
    result = subprocess.run(
        ["git", "-C", str(root), "show", "--unified=0", "--format=", commit_hash],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return
    yield from _iter_added_lines(result.stdout)


def scan_git_history(
    root: "str | Path",
    *,
    allowlist: Allowlist | None = None,
    entropy_config: EntropyConfig | None = None,
    since: str | None = None,
    max_commits: int | None = None,
) -> list[Finding]:
    root = Path(root)
    if not is_git_repo(root):
        return []

    allowlist = allowlist or Allowlist()
    findings: list[Finding] = []

    for commit in list_commits(root, since=since, max_commits=max_commits):
        commit_meta = {
            "commit_hash": commit.commit_hash[:12],
            "commit_author": commit.author,
            "commit_date": commit.date,
            "commit_subject": commit.subject,
        }
        for file_path, line_no, line in commit_added_lines(root, commit.commit_hash):
            if allowlist.is_path_ignored(file_path):
                continue
            findings.extend(
                scan_line(
                    line,
                    file_path=file_path,
                    line_number=line_no,
                    allowlist=allowlist,
                    entropy_config=entropy_config,
                    source="git_history",
                    commit_meta=commit_meta,
                )
            )

    return dedupe(findings)
