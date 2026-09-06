"""Walks a file or directory tree and runs the security rules over every
Python file found, aggregating the results into a single scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .rules import Finding, scan_source

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "env", "node_modules", ".mypy_cache", ".pytest_cache", "build", "dist"}


@dataclass
class ScanResult:
    root: str
    files_scanned: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    parse_errors: list[tuple[str, str]] = field(default_factory=list)  # (file, message)


def discover_python_files(root: str | Path) -> list[Path]:
    root = Path(root)
    if root.is_file():
        return [root] if root.suffix == ".py" else []

    files = []
    for path in sorted(root.rglob("*.py")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        files.append(path)
    return files


def scan_file(path: str | Path, root: str | Path | None = None) -> list[Finding]:
    """Scan a single Python file and return its findings.

    ``root`` is used only to compute the path shown in each :class:`Finding`
    (relative to the scan root); it defaults to the file's own parent.
    """
    path = Path(path)
    root = Path(root) if root is not None else path.parent
    try:
        display_name = str(path.relative_to(root))
    except ValueError:
        display_name = str(path)

    source = path.read_text(encoding="utf-8", errors="replace")
    return scan_source(source, filename=display_name)


def scan_directory(root: str | Path) -> ScanResult:
    root = Path(root)
    result = ScanResult(root=str(root))

    for path in discover_python_files(root):
        display_name = str(path.relative_to(root)) if root.is_dir() else path.name
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            findings = scan_source(source, filename=display_name)
        except SyntaxError as exc:
            result.parse_errors.append((display_name, str(exc)))
            continue
        result.files_scanned.append(display_name)
        result.findings.extend(findings)

    result.findings.sort(key=lambda f: (_SEVERITY_RANK[f.severity], f.file, f.line), reverse=False)
    return result


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
