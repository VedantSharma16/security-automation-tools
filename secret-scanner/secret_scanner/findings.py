"""The Finding record and severity scoring shared by scanner and report."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
SEVERITY_WEIGHT = {"low": 5, "medium": 15, "high": 30, "critical": 45}


def redact(value: str) -> str:
    """Mask a secret value for safe display: keep a few boundary chars only."""
    if len(value) <= 8:
        return value[0] + "*" * max(len(value) - 1, 0)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str  # "signature" or "entropy"
    severity: str
    file_path: str
    line_number: int
    redacted_value: str
    description: str
    source: str = "working_tree"  # or "git_history"
    entropy: float | None = None
    commit_hash: str | None = None
    commit_author: str | None = None
    commit_date: str | None = None
    commit_subject: str | None = None

    def dedup_key(self):
        # Same secret at the same location, regardless of which commit it
        # was seen in, is one leak -- de-dupe on file+line+redacted value.
        return (self.file_path, self.line_number, self.redacted_value, self.rule_id)

    def to_dict(self) -> dict:
        d = {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "redacted_value": self.redacted_value,
            "description": self.description,
            "source": self.source,
        }
        if self.entropy is not None:
            d["entropy"] = round(self.entropy, 2)
        if self.commit_hash:
            d["commit"] = {
                "hash": self.commit_hash,
                "author": self.commit_author,
                "date": self.commit_date,
                "subject": self.commit_subject,
            }
        return d


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    result = []
    for f in findings:
        key = f.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        result.append(f)
    return result


def risk_score(findings: list[Finding]) -> int:
    """0-100 score, saturating so a handful of criticals already reads as maximal risk."""
    score = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    return min(score, 100)


def highest_severity(findings: list[Finding]) -> str | None:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: SEVERITY_RANK[s])
