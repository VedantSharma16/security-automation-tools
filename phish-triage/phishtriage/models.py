"""Shared data structures."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

SEVERITY_WEIGHTS = {"low": 5, "medium": 15, "high": 30, "critical": 45}


@dataclass
class Link:
    href: str
    text: str = ""  # visible anchor text ("" for plain-text URLs)


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    auth: dict = field(default_factory=dict)  # {"spf": "pass", "dkim": ..., "dmarc": ...}
    received: list = field(default_factory=list)
    text: str = ""
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)


@dataclass
class Finding:
    rule: str
    severity: str  # low | medium | high | critical
    title: str
    detail: str
    mitre: str = ""
    evidence: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
