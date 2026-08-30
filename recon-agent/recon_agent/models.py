"""Shared data types for probing, findings, and agent state."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


@dataclass
class ProbeResult:
    """The outcome of a single read-only HTTP GET against one URL."""

    url: str
    ok: bool
    status_code: int | None = None
    headers: dict = field(default_factory=dict)
    elapsed_ms: float | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "ok": self.ok,
            "status_code": self.status_code,
            "headers": self.headers,
            "elapsed_ms": round(self.elapsed_ms, 1) if self.elapsed_ms is not None else None,
            "error": self.error,
        }


@dataclass
class TLSResult:
    """The outcome of a TLS handshake probe against one host:port."""

    host: str
    port: int
    ok: bool
    version: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    issuer: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "ok": self.ok,
            "version": self.version,
            "not_after": self.not_after,
            "days_until_expiry": self.days_until_expiry,
            "issuer": self.issuer,
            "error": self.error,
        }


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    category: str
    evidence: str
    recommendation: str
    source_url: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "source_url": self.source_url,
        }


@dataclass
class AgentStep:
    """One iteration of the agent's think-act-observe loop."""

    tool: str
    args: dict
    result: object
    note: str = ""

    def to_dict(self) -> dict:
        result = self.result
        if hasattr(result, "to_dict"):
            result = result.to_dict()
        elif isinstance(result, list):
            result = [r.to_dict() if hasattr(r, "to_dict") else r for r in result]
        return {"tool": self.tool, "args": self.args, "result": result, "note": self.note}
