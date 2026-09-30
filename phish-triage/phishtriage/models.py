from __future__ import annotations

from dataclasses import dataclass, field, asdict

SEVERITY_WEIGHTS = {"low": 5, "medium": 15, "high": 30, "critical": 45}


@dataclass
class Finding:
    rule: str
    severity: str  # low | medium | high | critical
    description: str
    evidence: str = ""
    mitre: str = ""  # ATT&CK technique id, e.g. T1566.002

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Url:
    href: str
    text: str = ""  # visible anchor text, if any
    host: str = ""


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int = 0


@dataclass
class ParsedEmail:
    from_display: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    auth_results: str = ""
    received_spf: str = ""
    body_text: str = ""
    urls: list[Url] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)


@dataclass
class Verdict:
    score: int
    label: str
    findings: list[Finding]

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "label": self.label,
            "findings": [f.to_dict() for f in self.findings],
        }
