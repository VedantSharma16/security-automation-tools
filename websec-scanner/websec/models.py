"""Shared data model for scan findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Ordering used for sorting/filtering; higher index = more severe.
SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class Finding:
    """A single scan result, produced by a check module."""

    check: str
    severity: Severity
    title: str
    url: str
    detail: str = ""
    evidence: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": self.severity.value,
            "title": self.title,
            "url": self.url,
            "detail": self.detail,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass
class Endpoint:
    """A discovered URL with query parameters, used as an injection-probe target."""

    url: str
    params: dict = field(default_factory=dict)
    method: str = "GET"
    source: str = "crawl"
