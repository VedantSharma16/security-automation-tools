"""Scanning a directory's working tree for hardcoded secrets."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import entropy as entropy_mod
from .allowlist import Allowlist
from .rules import DEFAULT_RULES, redact

# Directories that are never source-of-truth for secrets and are either huge
# (dependency trees) or already covered another way (.git is handled by
# secretscan.git_history, not walked as plain files here).
DEFAULT_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        "dist",
        "build",
        "site-packages",
        ".idea",
        ".vscode",
        "vendor",
    }
)

# Extensions that are essentially never useful to scan and are common enough
# to matter for scan speed on large repos.
DEFAULT_SKIP_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
        ".woff", ".woff2", ".ttf", ".eot",
        ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
        ".pdf", ".mp3", ".mp4", ".mov", ".avi", ".wav",
        ".pyc", ".pyo", ".so", ".dll", ".dylib", ".class", ".jar",
        ".lock",
    }
)

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MiB


@dataclass(frozen=True)
class Finding:
    file: str
    line_number: int
    rule_id: str
    severity: str
    description: str
    redacted_secret: str
    line_preview: str
    source: str = "working-tree"
    commit: str | None = None

    def to_dict(self) -> dict:
        d = {
            "file": self.file,
            "line": self.line_number,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "description": self.description,
            "secret": self.redacted_secret,
            "context": self.line_preview,
            "source": self.source,
        }
        if self.commit:
            d["commit"] = self.commit
        return d


def is_probably_binary(sample: bytes) -> bool:
    if b"\x00" in sample:
        return True
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
    nontext = sample.translate(None, delete=bytes(text_chars))
    return len(nontext) / max(len(sample), 1) > 0.30


def iter_scannable_files(root: Path, skip_dirs: frozenset = DEFAULT_SKIP_DIRS):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.relative_to(root).parts[:-1]):
            continue
        if path.suffix.lower() in DEFAULT_SKIP_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan_text(
    text: str,
    *,
    file_label: str,
    rules=DEFAULT_RULES,
    use_entropy: bool = True,
    source: str = "working-tree",
    commit: str | None = None,
    allowlist: Allowlist | None = None,
) -> list:
    """Scan raw text content line-by-line and return a list of Findings.

    Shared by the working-tree scanner (reads a file) and the git-history
    scanner (reads a blob/diff-hunk's text), so both stay in sync. The
    allowlist is applied here, against the *raw* matched value, rather than
    by the caller after redaction -- literal/regex allowlist entries need
    the real value to match against, since the redacted form (``ak**...**34``)
    is deliberately lossy.
    """
    allowlist = allowlist or Allowlist()
    findings: list = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:
            # Minified/bundled JS and data blobs on one line: skip to avoid
            # pathological regex backtracking and useless noise.
            continue

        matched_spans: list = []
        for rule in rules:
            for match in rule.pattern.finditer(line):
                span, matched_text = rule.extract(match)
                matched_spans.append((span, rule, matched_text))

        # A generic-secret assignment rule (e.g. generic-api-key-assignment)
        # can overlap a more specific one (e.g. aws-access-key-id) matching
        # inside the same quoted value; keep only the most specific rule per
        # overlapping span so one secret isn't reported twice.
        matched_spans.sort(key=lambda item: (item[0][0], item[0][0] - item[0][1]))
        kept: list = []
        for span, rule, text_match in matched_spans:
            if any(span[0] < k_span[1] and k_span[0] < span[1] for k_span, _, _ in kept):
                continue
            kept.append((span, rule, text_match))

        for _, rule, matched_text in kept:
            if allowlist.is_allowed(file_path=file_label, rule_id=rule.id, matched_text=matched_text):
                continue
            findings.append(
                Finding(
                    file=file_label,
                    line_number=line_number,
                    rule_id=rule.id,
                    severity=rule.severity,
                    description=rule.description,
                    redacted_secret=redact(matched_text, rule.redact),
                    line_preview=line.strip()[:200],
                    source=source,
                    commit=commit,
                )
            )

        if use_entropy:
            covered = [span for span, _, _ in kept]
            for candidate in entropy_mod.find_high_entropy_assignments(line):
                start = line.find(candidate.value)
                span = (start, start + len(candidate.value)) if start >= 0 else (0, 0)
                if any(span[0] < c[1] and c[0] < span[1] for c in covered):
                    continue
                if allowlist.is_allowed(
                    file_path=file_label,
                    rule_id="generic-high-entropy-secret",
                    matched_text=candidate.value,
                ):
                    continue
                findings.append(
                    Finding(
                        file=file_label,
                        line_number=line_number,
                        rule_id="generic-high-entropy-secret",
                        severity="low",
                        description=(
                            f"High-entropy value ({candidate.entropy:.1f} bits/char) assigned to "
                            f"'{candidate.variable_name}', a security-sounding name with no matching "
                            "known secret format."
                        ),
                        redacted_secret=redact(candidate.value, "partial"),
                        line_preview=line.strip()[:200],
                        source=source,
                        commit=commit,
                    )
                )
    return findings


def scan_file(
    path: Path,
    *,
    file_label: str | None = None,
    rules=DEFAULT_RULES,
    use_entropy: bool = True,
    allowlist: Allowlist | None = None,
) -> list:
    try:
        sample = path.open("rb").read(8192)
    except OSError:
        return []
    if is_probably_binary(sample):
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return scan_text(
        text, file_label=file_label or str(path), rules=rules, use_entropy=use_entropy, allowlist=allowlist
    )


def scan_directory(
    root: Path,
    *,
    rules=DEFAULT_RULES,
    use_entropy: bool = True,
    allowlist: Allowlist | None = None,
) -> list:
    """Scan every text file under ``root`` and return allowlist-filtered Findings."""
    root = Path(root).resolve()
    allowlist = allowlist or Allowlist()
    findings: list = []
    for path in iter_scannable_files(root):
        rel_path = str(path.relative_to(root))
        findings.extend(
            scan_file(path, file_label=rel_path, rules=rules, use_entropy=use_entropy, allowlist=allowlist)
        )
    return findings
