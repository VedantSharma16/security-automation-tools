"""File-tree and git-history scanning: turns raw detector hits into `Finding`s."""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from secret_scanner.detectors import scan_text

DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".tox",
        "site-packages",
        "vendor",
    }
)

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # skip anything bigger; unlikely to hold hand-typed secrets
_REDACT_KEEP = 4  # leading/trailing characters shown when redacting a secret


@dataclass(frozen=True)
class Finding:
    rule_id: str
    description: str
    severity: str
    file_path: str
    line_number: int
    secret: str
    line_text: str
    commit: str | None = None
    author: str | None = None
    date: str | None = None

    @property
    def redacted_secret(self) -> str:
        return redact(self.secret)

    @property
    def redacted_line(self) -> str:
        if self.secret and self.secret in self.line_text:
            return self.line_text.replace(self.secret, self.redacted_secret)
        return redact(self.line_text)

    @property
    def fingerprint(self) -> str:
        """Stable identity for baseline suppression: survives line-number drift."""
        digest = hashlib.sha256(f"{self.rule_id}:{self.file_path}:{self.secret}".encode()).hexdigest()
        return digest[:16]


def redact(value: str) -> str:
    if len(value) <= _REDACT_KEEP * 2:
        return "*" * len(value)
    return value[:_REDACT_KEEP] + "*" * (len(value) - _REDACT_KEEP * 2) + value[-_REDACT_KEEP:]


def is_probably_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def iter_scannable_files(root: Path, exclude_dirs: frozenset[str] = DEFAULT_EXCLUDE_DIRS):
    root = Path(root)
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in exclude_dirs for part in path.parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
            with path.open("rb") as fh:
                if is_probably_binary(fh.read(8000)):
                    continue
        except OSError:
            continue
        yield path


def _offset_to_line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_file_content(text: str, file_path: str) -> list[Finding]:
    lines = text.splitlines()
    findings = []
    for match in scan_text(text):
        line_no = _offset_to_line(text, match.start)
        line_text = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
        findings.append(
            Finding(
                rule_id=match.rule_id,
                description=match.description,
                severity=match.severity,
                file_path=file_path,
                line_number=line_no,
                secret=match.matched_text,
                line_text=line_text,
            )
        )
    return findings


def scan_paths(paths: list[Path], exclude_dirs: frozenset[str] = DEFAULT_EXCLUDE_DIRS) -> list[Finding]:
    """Scan the current working tree (files as they exist on disk now)."""
    findings: list[Finding] = []
    for path in paths:
        for file_path in iter_scannable_files(path, exclude_dirs):
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(scan_file_content(text, str(file_path)))
    return findings


# --- git history scanning -------------------------------------------------

_COMMIT_MARKER = "\x02COMMIT\x02"
_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<new_start>\d+)(?:,\d+)? @@")
_DIFF_FILE_RE = re.compile(r"^diff --git a/.* b/(?P<path>.*)$")


@dataclass
class _CommitDiffState:
    commit: str | None = None
    author: str | None = None
    date: str | None = None
    file_path: str | None = None
    new_line_no: int = 0
    binary: bool = False


def _run_git_log(repo_path: Path, max_commits: int | None) -> str:
    log_format = f"{_COMMIT_MARKER}%H%x01%an%x01%ad"
    cmd = [
        "git",
        "-C",
        str(repo_path),
        "log",
        "--all",
        "--no-color",
        "--date=short",
        "--unified=0",
        "-p",
        f"--format={log_format}",
    ]
    if max_commits is not None:
        cmd.insert(cmd.index("log") + 1, f"-{max_commits}")
    result = subprocess.run(
        cmd,
        cwd=str(repo_path),
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    return result.stdout


def _parse_git_log(raw_output: str):
    """Yield (commit, author, date, file_path, line_no, added_line_text) tuples."""
    state = _CommitDiffState()
    for raw_line in raw_output.splitlines():
        if raw_line.startswith(_COMMIT_MARKER):
            rest = raw_line[len(_COMMIT_MARKER) :]
            parts = rest.split("\x01")
            state = _CommitDiffState(
                commit=parts[0] if len(parts) > 0 else None,
                author=parts[1] if len(parts) > 1 else None,
                date=parts[2] if len(parts) > 2 else None,
            )
            continue

        file_match = _DIFF_FILE_RE.match(raw_line)
        if file_match:
            state.file_path = file_match.group("path")
            state.binary = False
            continue

        if raw_line.startswith("Binary files ") and raw_line.endswith(" differ"):
            state.binary = True
            continue

        if state.binary:
            continue

        hunk_match = _HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            state.new_line_no = int(hunk_match.group("new_start"))
            continue

        if raw_line.startswith("+++") or raw_line.startswith("---"):
            continue

        if raw_line.startswith("+"):
            if state.file_path is not None:
                yield state.commit, state.author, state.date, state.file_path, state.new_line_no, raw_line[1:]
            state.new_line_no += 1
        elif raw_line.startswith(" "):
            state.new_line_no += 1
        # lines starting with '-' (removals) don't advance the new-file counter


def scan_git_history(repo_path: Path, max_commits: int | None = None) -> list[Finding]:
    """Scan every added line across the full git history (including deleted-but-once-committed secrets)."""
    raw_output = _run_git_log(Path(repo_path), max_commits)
    findings: list[Finding] = []
    for commit, author, date, file_path, line_no, line_text in _parse_git_log(raw_output):
        for match in scan_text(line_text):
            findings.append(
                Finding(
                    rule_id=match.rule_id,
                    description=match.description,
                    severity=match.severity,
                    file_path=file_path,
                    line_number=line_no,
                    secret=match.matched_text,
                    line_text=line_text,
                    commit=commit,
                    author=author,
                    date=date,
                )
            )
    return findings
