"""File and working-tree scanning: turns lines of text into Findings."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .allowlist import Allowlist
from .entropy import EntropyConfig, find_high_entropy_tokens
from .findings import Finding, dedupe, redact
from .signatures import SIGNATURES

_BINARY_PROBE_BYTES = 8192


def is_probably_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(_BINARY_PROBE_BYTES)
    except OSError:
        return True
    return b"\x00" in chunk


def scan_line(
    line: str,
    *,
    file_path: str,
    line_number: int,
    allowlist: Allowlist,
    entropy_config: EntropyConfig | None,
    source: str = "working_tree",
    commit_meta: dict | None = None,
) -> list[Finding]:
    """Run every signature (and, if enabled, entropy scan) over one line."""
    if allowlist.is_line_suppressed(line):
        return []

    findings: list[Finding] = []
    covered_spans: list[tuple] = []
    commit_meta = commit_meta or {}

    for sig in SIGNATURES:
        for match in sig.pattern.finditer(line):
            value = sig.secret_value(match)
            if allowlist.is_value_placeholder(value):
                continue
            findings.append(
                Finding(
                    rule_id=sig.id,
                    category="signature",
                    severity=sig.severity,
                    file_path=file_path,
                    line_number=line_number,
                    redacted_value=redact(value),
                    description=sig.description,
                    source=source,
                    **commit_meta,
                )
            )
            covered_spans.append(match.span())

    if entropy_config is not None:
        for token, start, end, entropy in find_high_entropy_tokens(line, entropy_config):
            if any(start < c_end and end > c_start for c_start, c_end in covered_spans):
                continue  # already reported by a more specific signature
            if allowlist.is_value_placeholder(token):
                continue
            findings.append(
                Finding(
                    rule_id="high-entropy-string",
                    category="entropy",
                    severity="low" if entropy < entropy_config.base64_threshold + 0.3 else "medium",
                    file_path=file_path,
                    line_number=line_number,
                    redacted_value=redact(token),
                    description="High-entropy string with no matching known secret format",
                    source=source,
                    entropy=entropy,
                    **commit_meta,
                )
            )

    return findings


def scan_text(
    text: str,
    *,
    file_path: str,
    allowlist: Allowlist,
    entropy_config: EntropyConfig | None,
    source: str = "working_tree",
    commit_meta: dict | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        findings.extend(
            scan_line(
                line,
                file_path=file_path,
                line_number=i,
                allowlist=allowlist,
                entropy_config=entropy_config,
                source=source,
                commit_meta=commit_meta,
            )
        )
    return findings


def scan_file(
    path: Path,
    *,
    repo_relative: str,
    allowlist: Allowlist,
    entropy_config: EntropyConfig | None,
) -> list[Finding]:
    if is_probably_binary(path):
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return scan_text(
        text,
        file_path=repo_relative,
        allowlist=allowlist,
        entropy_config=entropy_config,
    )


def _git_tracked_files(root: Path) -> list[str] | None:
    """Return git-tracked + untracked-but-not-ignored files, or None if `root`
    isn't a git working tree (caller then falls back to a plain walk)."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return [line for line in result.stdout.splitlines() if line]


def iter_scan_targets(root: Path, allowlist: Allowlist) -> list[str]:
    """List repo-relative file paths to scan, preferring git's own file list
    (which already honors .gitignore) and falling back to os.walk."""
    tracked = _git_tracked_files(root)
    if tracked is not None:
        candidates = tracked
    else:
        candidates = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {".git"}]
            for name in filenames:
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                candidates.append(Path(rel).as_posix())

    return [c for c in candidates if not allowlist.is_path_ignored(c)]


def scan_working_tree(
    root: "str | Path",
    *,
    allowlist: Allowlist | None = None,
    entropy_config: EntropyConfig | None = None,
) -> list[Finding]:
    root = Path(root)
    allowlist = allowlist or Allowlist()
    findings: list[Finding] = []
    for rel_path in iter_scan_targets(root, allowlist):
        full_path = root / rel_path
        if not full_path.is_file():
            continue
        findings.extend(
            scan_file(
                full_path,
                repo_relative=rel_path,
                allowlist=allowlist,
                entropy_config=entropy_config,
            )
        )
    return dedupe(findings)
