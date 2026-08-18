"""Language-agnostic secret detection: known credential formats + entropy heuristics."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from codesec.entropy import looks_like_secret
from codesec.findings import Finding, Severity

# (rule_id, title, compiled regex, cwe) — regex must capture the secret in group 1
# where possible so it can be redacted in the snippet.
_KNOWN_PATTERNS = [
    (
        "secret-aws-access-key",
        "AWS Access Key ID",
        re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        "CWE-798",
    ),
    (
        "secret-aws-secret-key",
        "Potential AWS Secret Access Key",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "CWE-798",
    ),
    (
        "secret-github-token",
        "GitHub Personal Access Token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
        "CWE-798",
    ),
    (
        "secret-slack-token",
        "Slack Token",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b"),
        "CWE-798",
    ),
    (
        "secret-private-key",
        "Private Key Material",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "CWE-321",
    ),
    (
        "secret-jwt",
        "Hardcoded JSON Web Token",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        "CWE-798",
    ),
    (
        "secret-slack-webhook",
        "Slack Webhook URL",
        re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,})"),
        "CWE-798",
    ),
    (
        "secret-generic-assignment",
        "Hardcoded Credential Assignment",
        re.compile(
            # No leading \b: variable names like `db_password` or `DB_PASSWORD`
            # should still match even though `_` is a \w character that would
            # otherwise suppress the boundary before "password".
            r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
            r"auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*"
            r"['\"]([^'\"\s]{8,})['\"]"
        ),
        "CWE-798",
    ),
]

# Assignment-style lines worth an entropy check even without a "password"-like name,
# e.g. `token = "..."` or `X_API_TOKEN = "..."`.
_GENERIC_ASSIGNMENT = re.compile(r"""['"]([A-Za-z0-9+/=_\-\.]{20,})['"]""")

_SKIP_DIR_NAMES = frozenset(
    {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache"}
)

_DEFAULT_EXTENSIONS = frozenset(
    {".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml", ".env", ".cfg", ".ini", ".toml", ".sh", ".txt"}
)


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"


def iter_scannable_files(root: Path, extensions: frozenset = _DEFAULT_EXTENSIONS) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() in extensions or path.name.lower() in {".env"}:
            yield path


def scan_text(text: str, file_label: str) -> list:
    findings = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        matched_known = False
        for rule_id, title, pattern, cwe in _KNOWN_PATTERNS:
            for match in pattern.finditer(line):
                matched_known = True
                secret = match.group(1) if match.groups() else match.group(0)
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        title=title,
                        severity=Severity.CRITICAL,
                        cwe=cwe,
                        file=file_label,
                        line=lineno,
                        column=match.start() + 1,
                        snippet=line.strip().replace(secret, _redact(secret)),
                        description=f"{title} appears to be hardcoded in source.",
                        remediation=(
                            "Remove the credential from source control, rotate it immediately, "
                            "and load it from a secrets manager or environment variable instead."
                        ),
                    )
                )

        if matched_known:
            continue

        for match in _GENERIC_ASSIGNMENT.finditer(line):
            token = match.group(1)
            if looks_like_secret(token):
                findings.append(
                    Finding(
                        rule_id="secret-high-entropy-string",
                        title="High-Entropy String (Possible Secret)",
                        severity=Severity.MEDIUM,
                        cwe="CWE-798",
                        file=file_label,
                        line=lineno,
                        column=match.start() + 1,
                        snippet=line.strip().replace(token, _redact(token)),
                        description=(
                            "A long, high-entropy string was found that resembles an API key "
                            "or token but did not match a known credential format."
                        ),
                        remediation=(
                            "Verify whether this value is sensitive. If it is, move it out of "
                            "source control and rotate it."
                        ),
                    )
                )
    return findings


def scan_path(root: Path) -> list:
    findings = []
    for file_path in iter_scannable_files(root):
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(scan_text(text, str(file_path)))
    return findings
