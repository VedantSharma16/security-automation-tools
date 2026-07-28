"""Shared data structures for recon results and findings."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Subdomain:
    name: str
    ip: str | None


@dataclass(frozen=True)
class OpenPort:
    port: int
    service: str
    sensitive: bool


@dataclass(frozen=True)
class Finding:
    """A single audit finding (missing header, weak cert, exposed port, ...)."""

    category: str  # "port", "header", "tls", "banner"
    severity: str  # "info", "low", "medium", "high", "critical"
    title: str
    detail: str


@dataclass
class HostReport:
    host: str
    ip: str | None
    open_ports: list[OpenPort] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "info"
    errors: list[str] = field(default_factory=list)
