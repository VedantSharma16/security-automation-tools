"""The Indicator record every analyzer emits, plus severity weights and ATT&CK labels."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {"info": 0, "low": 5, "medium": 15, "high": 30, "critical": 45}

MITRE = {
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1656": "Impersonation",
    "T1036.007": "Masquerading: Double File Extension",
    "T1027.006": "Obfuscated Files or Information: HTML Smuggling",
    "T1204.002": "User Execution: Malicious File",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1036.002": "Masquerading: Right-to-Left Override",
}


@dataclass
class Indicator:
    id: str
    category: str  # authentication | sender | url | attachment | content
    severity: str
    title: str
    detail: str
    evidence: str = ""
    mitre: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_WEIGHT:
            raise ValueError(f"unknown severity: {self.severity}")

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT[self.severity]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["mitre"] = [{"id": t, "name": MITRE.get(t, "")} for t in self.mitre]
        return d
