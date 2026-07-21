"""Shared data structures for the scanner, checks, grading, and reporting layers."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    description: str
    remediation: str
    evidence: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}, must be one of {SEVERITIES}")


@dataclass
class ScanTarget:
    """Result of fetching a URL: headers, cookies, and an optional CORS probe."""

    url: str
    final_url: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)
    cors_test_headers: dict[str, str] | None = None
    cors_test_origin: str | None = None
    elapsed_ms: float = 0.0

    def get_header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


@dataclass
class TLSInfo:
    """Result of a raw TLS handshake against a host:port, independent of the HTTP layer."""

    hostname: str
    port: int
    protocol_version: str | None = None
    cipher: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    issuer: str | None = None
    subject: str | None = None
    san: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class ScanResult:
    target_url: str
    findings: list[Finding]
    score: int
    grade: str
    tls: TLSInfo | None = None
    scanned_at: str = ""
