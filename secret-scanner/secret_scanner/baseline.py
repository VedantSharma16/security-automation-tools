"""Baseline / allowlist support so accepted false positives don't re-alert forever.

Mirrors the workflow tools like gitleaks/detect-secrets use: run a scan, review
the findings, decide some are known-safe (test fixtures, rotated keys, docs
examples), and record their fingerprints in a baseline file. Future scans still
run every rule but drop anything whose fingerprint is already in the baseline.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from secret_scanner.scanner import Finding

DEFAULT_BASELINE_FILENAME = ".secret-scanner-baseline.json"


@dataclass(frozen=True)
class BaselineEntry:
    fingerprint: str
    rule_id: str
    file_path: str
    reason: str = ""


class Baseline:
    def __init__(self, entries: dict[str, BaselineEntry] | None = None):
        self._entries: dict[str, BaselineEntry] = entries or {}

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, fingerprint: str) -> bool:
        return fingerprint in self._entries

    def add(self, finding: Finding, reason: str = "") -> None:
        self._entries[finding.fingerprint] = BaselineEntry(
            fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            reason=reason,
        )

    def filter_findings(self, findings: list[Finding]) -> list[Finding]:
        """Return only findings whose fingerprint is NOT in the baseline."""
        return [f for f in findings if f.fingerprint not in self._entries]

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "entries": [asdict(entry) for entry in self._entries.values()],
        }

    def save(self, path: Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        entries = {}
        for raw in data.get("entries", []):
            entry = BaselineEntry(
                fingerprint=raw["fingerprint"],
                rule_id=raw.get("rule_id", ""),
                file_path=raw.get("file_path", ""),
                reason=raw.get("reason", ""),
            )
            entries[entry.fingerprint] = entry
        return cls(entries)

    @classmethod
    def load(cls, path: Path) -> "Baseline":
        path = Path(path)
        if not path.exists():
            return cls()
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    @classmethod
    def from_findings(cls, findings: list[Finding], reason: str = "reviewed: accepted as safe") -> "Baseline":
        baseline = cls()
        for finding in findings:
            baseline.add(finding, reason=reason)
        return baseline
