"""Filesystem scanning: walk a directory tree and flag likely secrets."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .entropy import find_high_entropy_tokens
from .patterns import PATTERNS, redact

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
}

# Suppress a single line, mirroring the convention used by detect-secrets /
# gitleaks so existing allowlist comments in a codebase are respected.
SUPPRESSION_MARKERS = ("pragma: allowlist secret", "secretscanner: ignore")

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # skip anything above 2MB (binaries, dumps)


@dataclass(frozen=True)
class Finding:
    file: str
    line_number: int
    pattern_name: str
    category: str
    severity: str
    detector: str  # "regex" or "entropy"
    redacted_value: str
    remediation: str
    line_preview: str = field(compare=False)


def _is_suppressed(line: str) -> bool:
    return any(marker in line for marker in SUPPRESSION_MARKERS)


def _preview(line: str, limit: int = 160) -> str:
    stripped = line.strip()
    return stripped if len(stripped) <= limit else stripped[:limit] + "..."


def scan_text(text: str, file_label: str) -> list[Finding]:
    """Run pattern and entropy detection over a block of text (e.g. one file's
    contents, or the added lines of a git diff)."""
    findings: list[Finding] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        if _is_suppressed(line):
            continue

        matched_regex = False
        for pattern in PATTERNS:
            match = pattern.regex.search(line)
            if not match:
                continue
            matched_regex = True
            findings.append(
                Finding(
                    file=file_label,
                    line_number=line_number,
                    pattern_name=pattern.name,
                    category=pattern.category,
                    severity=pattern.severity,
                    detector="regex",
                    redacted_value=redact(match.group(0)),
                    remediation=pattern.remediation,
                    line_preview=_preview(line),
                )
            )

        # Entropy scanning is noisier than the vendor-specific regexes above,
        # so we only run it on lines a known pattern didn't already explain.
        if matched_regex:
            continue

        for token_match in find_high_entropy_tokens(line):
            findings.append(
                Finding(
                    file=file_label,
                    line_number=line_number,
                    pattern_name=f"High-entropy {token_match.alphabet} string",
                    category="generic",
                    severity="low",
                    detector="entropy",
                    redacted_value=redact(token_match.token),
                    remediation="Verify whether this is a live credential; if so, rotate and store it in a secrets manager.",
                    line_preview=_preview(line),
                )
            )

    return findings


def scan_file(path: Path) -> list[Finding]:
    try:
        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
            return []
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    return scan_text(text, file_label=str(path))


def scan_directory(
    root: Path, exclude_dirs: set[str] | None = None
) -> list[Finding]:
    exclude_dirs = exclude_dirs if exclude_dirs is not None else DEFAULT_EXCLUDE_DIRS
    findings: list[Finding] = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for name in filenames:
            findings.extend(scan_file(Path(dirpath) / name))

    return sorted(findings, key=lambda f: (f.file, f.line_number))
