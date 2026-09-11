"""Shared result type used by every check module."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

STATUS_PASS = "pass"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
STATUS_INFO = "info"

# Points deducted from a 100-point baseline for each fail/warn finding at a
# given severity. "info" findings (including passes) never deduct.
SEVERITY_WEIGHTS = {"info": 0, "low": 3, "medium": 8, "high": 15, "critical": 25}


@dataclass
class CheckResult:
    id: str
    category: str  # "headers" | "cookies" | "cors" | "tls" | "disclosure"
    status: str  # pass | warn | fail | info
    severity: str  # info | low | medium | high | critical
    title: str
    detail: str
    remediation: Optional[str] = None
