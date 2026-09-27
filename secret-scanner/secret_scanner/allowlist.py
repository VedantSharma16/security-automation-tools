"""False-positive suppression: paths, placeholder values, and inline ignores.

A signature or entropy hit is suppressed if any of the following hold:
  - it sits under a path that matches a default- or user-ignored directory
    / glob (build output, dependency trees, the scanner's own test fixtures)
  - the matched value itself looks like a placeholder ("changeme",
    "AKIAIOSFODNN7EXAMPLE", a string of one repeated character, etc.)
  - the source line carries an inline `secret-scanner:ignore` comment
  - the value is explicitly listed in a `.secretscanignore` file
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_IGNORED_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    "egg-info",
}

DEFAULT_IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".so", ".dll", ".exe",
    ".pyc", ".lock",
}

INLINE_SUPPRESS_MARKER = "secret-scanner:ignore"

_PLACEHOLDER_SUBSTRINGS = (
    "example", "placeholder", "changeme", "change_me", "your-api-key",
    "your_api_key", "dummy", "sample", "redacted", "xxxxxxxx", "insert-key",
    "insert_key", "replace-with", "replace_with", "fake", "notarealkey",
    "not-a-real", "test-secret", "test_secret",
)

# A handful of well-known values that providers themselves publish as
# documentation examples, so they should never trip a real finding.
_KNOWN_SAFE_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",  # AWS's own example access key ID (docs.aws.amazon.com)
}

_REPEATED_CHAR_RE = re.compile(r"^(.)\1*$")


@dataclass
class Allowlist:
    ignored_path_globs: tuple = ()
    ignored_value_patterns: tuple = ()

    def is_path_ignored(self, path: str) -> bool:
        parts = Path(path).parts
        if any(part in DEFAULT_IGNORED_DIRS for part in parts):
            return True
        if Path(path).suffix.lower() in DEFAULT_IGNORED_EXTENSIONS:
            return True
        normalized = Path(path).as_posix()
        return any(fnmatch.fnmatch(normalized, glob) for glob in self.ignored_path_globs)

    def is_value_placeholder(self, value: str) -> bool:
        if value in _KNOWN_SAFE_VALUES:
            return True
        lowered = value.lower()
        if any(sub in lowered for sub in _PLACEHOLDER_SUBSTRINGS):
            return True
        if _REPEATED_CHAR_RE.match(value):
            return True
        if any(re.search(pattern, value) for pattern in self.ignored_value_patterns):
            return True
        return False

    def is_line_suppressed(self, line: str) -> bool:
        return INLINE_SUPPRESS_MARKER in line


def load_allowlist_file(path: "str | Path") -> Allowlist:
    """Parse a `.secretscanignore` file: one entry per line.

    - Lines starting with `path:` are glob patterns matched against file paths.
    - Lines starting with `value:` are regexes matched against secret values.
    - Blank lines and lines starting with `#` are ignored.
    - A bare line (no prefix) is treated as a path glob, for convenience.
    """
    path_globs = []
    value_patterns = []
    text = Path(path).read_text(encoding="utf-8")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("path:"):
            path_globs.append(line[len("path:"):].strip())
        elif line.startswith("value:"):
            value_patterns.append(line[len("value:"):].strip())
        else:
            path_globs.append(line)
    return Allowlist(ignored_path_globs=tuple(path_globs), ignored_value_patterns=tuple(value_patterns))
