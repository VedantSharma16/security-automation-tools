"""Shared data model: severity scale and the Finding record every analysis module emits."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    detail: str
    category: str
    recommendation: str = ""
