from __future__ import annotations

from dataclasses import dataclass, field, asdict

SEVERITY_WEIGHTS = {"LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 45}


@dataclass
class Finding:
    rule: str
    severity: str
    description: str
    evidence: str = ""
    attack: str = ""  # MITRE ATT&CK technique id

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Verdict:
    score: int
    label: str
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"score": self.score, "label": self.label,
                "findings": [f.to_dict() for f in self.findings]}
