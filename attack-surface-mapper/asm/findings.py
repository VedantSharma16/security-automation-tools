"""Shared severity model and finding type used by every recon module.

Every module in this tool (DNS, subdomains, HTTP headers, TLS) reduces its
raw results down to a list of these `Finding` objects. Keeping one shared
shape means the report builder, risk scorer, and LLM summarizer don't need
to know anything about DNS or TLS specifically -- they only ever deal with
"a source produced a finding of this severity."
"""

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


_RISK_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}


@dataclass(frozen=True)
class Finding:
    source: str  # "dns" | "subdomains" | "http_headers" | "tls"
    severity: Severity
    title: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "severity": self.severity.name,
            "title": self.title,
            "detail": self.detail,
        }


def build_summary(findings: list[Finding]) -> dict:
    """Aggregate findings into a per-severity breakdown and a 0-100 risk score.

    INFO findings never contribute to the risk score -- they exist to make
    the report legible (e.g. "12 subdomains discovered"), not to flag risk.
    """
    by_severity = {s.name: 0 for s in Severity}
    for f in findings:
        by_severity[f.severity.name] += 1

    scoring_findings = [f for f in findings if f.severity is not Severity.INFO]
    risk_score = min(100, sum(_RISK_WEIGHT[f.severity] for f in scoring_findings))
    highest = max((f.severity for f in scoring_findings), default=None)

    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "risk_score": risk_score,
        "highest_severity": highest.name if highest else None,
    }
