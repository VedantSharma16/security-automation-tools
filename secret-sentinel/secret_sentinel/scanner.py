"""Filesystem scanning: walk a directory tree and apply signatures + entropy
detection to every text file, producing a list of :class:`Finding`.

Secrets are never stored or printed in full. Every finding keeps only a
redacted preview (first/last 4 characters) and a short, non-reversible
fingerprint derived from the value, used purely for baseline/allowlist
matching (see ``baseline.py``) — the fingerprint intentionally never appears
in the human-readable console report.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from .entropy import find_candidate_assignments, is_high_entropy_secret, is_placeholder, shannon_entropy
from .patterns import Signature

DEFAULT_IGNORE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist",
    "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "vendor",
    ".idea", ".vscode", "target", ".terraform",
}

DEFAULT_IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".pdf",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib",
    ".woff", ".woff2", ".ttf", ".eot", ".class", ".pyc", ".jar",
}

_IGNORE_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pipfile.lock",
    "poetry.lock", "cargo.lock", "composer.lock",
}

_IGNORE_LINE_MARKER = "secret-sentinel:ignore"

DEFAULT_MAX_FILE_SIZE = 2_000_000  # bytes
GENERIC_SIGNATURE_ID = "generic-high-entropy-string"


@dataclass(frozen=True)
class Finding:
    file: str
    line_number: int
    signature_id: str
    category: str
    severity: str
    confidence: str
    description: str
    redacted_value: str
    entropy: float
    fingerprint: str
    commit: str | None = field(default=None)

    def to_dict(self) -> dict:
        d = {
            "file": self.file,
            "line_number": self.line_number,
            "signature_id": self.signature_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "redacted_value": self.redacted_value,
            "entropy": self.entropy,
            "fingerprint": self.fingerprint,
        }
        if self.commit:
            d["commit"] = self.commit
        return d


def redact_secret(value: str) -> str:
    """Mask a secret value for safe display, keeping only a short prefix/suffix."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def compute_fingerprint(signature_id: str, value: str) -> str:
    """A short, one-way identifier for (signature, value), used for baselining.

    This is a convenience hash for deduplication/allowlisting, not a security
    boundary — a short SHA-256 prefix does not make the underlying secret
    safe to publish, so fingerprints are kept out of the console report.
    """
    digest = hashlib.sha256(f"{signature_id}:{value}".encode("utf-8")).hexdigest()
    return digest[:16]


def _is_binary_file(path: Path, sample_size: int = 8192) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(sample_size)
    except OSError:
        return True
    return b"\x00" in chunk


def should_skip_file(path: Path, max_size: int = DEFAULT_MAX_FILE_SIZE) -> bool:
    name = path.name.lower()
    if name in _IGNORE_FILENAMES:
        return True
    if name.endswith(".min.js") or name.endswith(".min.css"):
        return True
    if path.suffix.lower() in DEFAULT_IGNORE_EXTENSIONS:
        return True
    try:
        if path.stat().st_size > max_size:
            return True
    except OSError:
        return True
    return False


def iter_scannable_files(root, ignore_dirs: set[str] | None = None, max_size: int = DEFAULT_MAX_FILE_SIZE):
    """Yield every text file under ``root`` worth scanning."""
    root = Path(root)
    ignore_dirs = ignore_dirs if ignore_dirs is not None else DEFAULT_IGNORE_DIRS

    if root.is_file():
        if not should_skip_file(root, max_size) and not _is_binary_file(root):
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]
        for fname in filenames:
            candidate = Path(dirpath) / fname
            if should_skip_file(candidate, max_size):
                continue
            if _is_binary_file(candidate):
                continue
            yield candidate


def scan_line(
    line: str,
    signatures: list[Signature],
    entropy_threshold: float = 3.5,
    min_length: int = 12,
) -> list[dict]:
    """Apply every signature plus generic entropy detection to a single line.

    Returns a list of plain dicts (not tied to a file/line number yet) with
    keys matching the non-location fields of :class:`Finding`.
    """
    if _IGNORE_LINE_MARKER in line:
        return []

    results = []
    matched_spans: list[tuple[int, int]] = []

    for sig in signatures:
        for m in sig.pattern.finditer(line):
            value = m.groups()[-1] if m.lastindex else m.group(0)
            # Even a named signature can technically match a placeholder
            # (e.g. a generic assignment pattern matching `your-api-key-here`);
            # vendor-format signatures are rigid enough this rarely applies,
            # but it costs nothing to filter it out consistently everywhere.
            if is_placeholder(value):
                continue
            matched_spans.append((m.start(), m.end()))
            results.append(
                {
                    "signature_id": sig.id,
                    "category": sig.category,
                    "severity": sig.severity,
                    "confidence": sig.confidence,
                    "description": sig.description,
                    "redacted_value": redact_secret(value),
                    "entropy": round(shannon_entropy(value), 2),
                    "fingerprint": compute_fingerprint(sig.id, value),
                }
            )

    for var_name, value in find_candidate_assignments(line):
        idx = line.find(value)
        if idx != -1 and any(start <= idx < end for start, end in matched_spans):
            continue  # already reported by a more specific named signature
        if is_high_entropy_secret(value, threshold=entropy_threshold, min_length=min_length):
            results.append(
                {
                    "signature_id": GENERIC_SIGNATURE_ID,
                    "category": "generic-secret",
                    "severity": "medium",
                    "confidence": "low",
                    "description": (
                        f"Assignment to a '{var_name}'-like variable with a high-entropy "
                        f"value (entropy={shannon_entropy(value):.2f} bits/char)."
                    ),
                    "redacted_value": redact_secret(value),
                    "entropy": round(shannon_entropy(value), 2),
                    "fingerprint": compute_fingerprint(GENERIC_SIGNATURE_ID, value),
                }
            )

    return results


def scan_file(
    path: Path,
    signatures: list[Signature],
    entropy_threshold: float = 3.5,
    min_length: int = 12,
) -> list[Finding]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for hit in scan_line(line, signatures, entropy_threshold, min_length):
            findings.append(Finding(file=str(path), line_number=line_number, **hit))
    return findings


def scan_path(
    root,
    signatures: list[Signature],
    entropy_threshold: float = 3.5,
    min_length: int = 12,
    ignore_dirs: set[str] | None = None,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
) -> list[Finding]:
    """Scan every scannable file under ``root`` and return all findings."""
    findings = []
    for path in iter_scannable_files(root, ignore_dirs=ignore_dirs, max_size=max_size):
        findings.extend(scan_file(path, signatures, entropy_threshold, min_length))
    return findings
