"""The Finding type shared by the file scanner, the git-history scanner,
report rendering, baselining, and LLM triage.

A ``Finding`` never carries the raw secret past construction — only a
:func:`~secretscan.redact.redact`-ed preview and a stable fingerprint hash.
Every downstream consumer (console output, JSON, SARIF, the LLM triage
prompt) works from that redacted view.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


def make_fingerprint(rule_id: str, file_path: str, raw_text: str) -> str:
    """A stable identifier for a (rule, file, secret) triple.

    Deliberately excludes the line number: a finding should keep the same
    fingerprint (and stay allowlisted in the baseline) even after unrelated
    edits shift it a few lines up or down in the file.
    """
    digest = hashlib.sha256(f"{rule_id}|{file_path}|{raw_text}".encode("utf-8")).hexdigest()
    return digest[:16]


@dataclass
class Finding:
    rule_id: str
    severity: str
    category: str
    description: str
    file_path: str
    redacted: str
    fingerprint: str
    source: str  # "working-tree" or "git-history"
    line: int | None = None
    context_key: str | None = None  # variable/key name near the match, if any
    commit: str | None = None
    author: str | None = None
    date: str | None = None
    confidence: str = "high"
    triage_reason: str = "signature match"
    extra_tags: tuple = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "file_path": self.file_path,
            "line": self.line,
            "context_key": self.context_key,
            "redacted_secret": self.redacted,
            "fingerprint": self.fingerprint,
            "source": self.source,
            "commit": self.commit,
            "author": self.author,
            "date": self.date,
            "confidence": self.confidence,
            "triage_reason": self.triage_reason,
        }
