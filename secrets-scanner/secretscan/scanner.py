"""Top-level orchestration: file scan + optional git-history scan + baseline."""

from __future__ import annotations

from pathlib import Path

from . import filescan, gitscan
from .baseline import apply_baseline


def scan(root: Path, rules: list, include_history: bool = False, baseline: set | None = None) -> list:
    """Run the configured scans under ``root`` and return surviving Findings."""
    findings = filescan.scan_working_tree(root, rules)

    if include_history:
        if not gitscan.is_git_repo(root):
            raise gitscan.GitCommandError(f"{root} is not a git repository; can't scan history")
        findings.extend(gitscan.scan_git_history(root, rules))

    if baseline:
        findings = apply_baseline(findings, baseline)

    return findings
