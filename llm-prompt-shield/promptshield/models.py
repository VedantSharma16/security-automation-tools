from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str          # e.g. prompt_injection, jailbreak, secret, pii, exfiltration, obfuscation
    severity: Severity
    description: str
    excerpt: str
    owasp: str             # OWASP Top 10 for LLM Applications reference
    decoded: bool = False  # True when found inside a decoded (e.g. base64) payload

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass
class ScanResult:
    direction: str
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "allow"   # allow | review | block

    @property
    def categories(self) -> set[str]:
        return {f.category for f in self.findings}

    def to_dict(self) -> dict:
        return {
            "direction": self.direction,
            "verdict": self.verdict,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
        }
