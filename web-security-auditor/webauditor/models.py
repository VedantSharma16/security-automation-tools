"""Shared result types used across the header, cookie, and TLS checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    ORDER = (CRITICAL, HIGH, MEDIUM, LOW, INFO)


class Status:
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class Finding:
    check_id: str
    title: str
    status: str
    severity: str
    message: str
    remediation: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "remediation": self.remediation,
        }
