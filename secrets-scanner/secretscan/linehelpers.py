"""Small text helpers shared by the file scanner and the git-history scanner."""

from __future__ import annotations

import re

_CONTEXT_KEY_RE = re.compile(r"""^\s*["']?([A-Za-z_][A-Za-z0-9_\-]{1,60})["']?\s*[:=]""")

# Extensions we never treat as text, regardless of a sniffed null byte.
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".whl", ".pyc", ".so", ".dll", ".exe", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".mov", ".class", ".jar",
}

# Paths that are rarely worth scanning and slow a scan down a lot.
DEFAULT_IGNORE_DIRS = {
    ".git", "node_modules", "vendor", "venv", ".venv", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
}


def extract_context_key(line: str) -> str | None:
    """Best-effort variable/key name a ``KEY = value`` or ``key: value`` line assigns to."""
    m = _CONTEXT_KEY_RE.match(line)
    return m.group(1) if m else None


def looks_binary(sample: bytes) -> bool:
    """Heuristic: a null byte in the first chunk of a file usually means binary."""
    return b"\x00" in sample
