"""Orchestrates header, path, and TLS checks into one scan report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .fetcher import Fetcher, normalize_base_url
from .findings import Finding
from .headers import analyze_headers
from .llm_summarizer import LLMSummarizer
from .paths import PathRule, probe_sensitive_paths
from .scoring import RiskAssessment, assess_risk
from .tls_check import analyze_tls, inspect_tls


@dataclass
class ScanReport:
    target: str
    scanned_at: str
    findings: list[Finding]
    risk: RiskAssessment
    llm_backed: bool
    summary: str | None = None
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "scanned_at": self.scanned_at,
            "risk": {
                "score": self.risk.score,
                "overall_severity": self.risk.overall_severity,
                "severity_counts": self.risk.severity_counts,
            },
            "llm_backed": self.llm_backed,
            "summary": self.summary,
            "findings": [f.as_dict() for f in self.findings],
            "errors": self.errors,
        }


def scan_target(
    target: str,
    fetcher: Fetcher | None = None,
    check_tls: bool = True,
    path_rules: list[PathRule] | None = None,
    summarizer: LLMSummarizer | None = None,
) -> ScanReport:
    """Run the full check suite against one target and return a ScanReport.

    ``target`` may be a bare host (``example.com``) or a full URL; it is
    normalized to ``scheme://host[:port]`` before any probing starts.
    """
    fetcher = fetcher or Fetcher()
    base_url = normalize_base_url(target)
    parts = urlsplit(base_url)

    findings: list[Finding] = []
    errors: list[str] = []

    index = fetcher.get(base_url)
    if not index.ok:
        errors.append(f"Could not reach {base_url}: {index.error}")
    else:
        findings += analyze_headers(index, parts.scheme)

    findings += probe_sensitive_paths(fetcher, base_url, path_rules)

    if check_tls and parts.scheme == "https":
        port = parts.port or 443
        tls_info = inspect_tls(parts.hostname, port)
        findings += analyze_tls(tls_info)

    risk = assess_risk(findings)

    summary = None
    llm_backed = False
    if summarizer is not None:
        summary = summarizer.summarize(base_url, findings, risk)
        llm_backed = summarizer.is_live

    return ScanReport(
        target=base_url,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        risk=risk,
        llm_backed=llm_backed,
        summary=summary,
        errors=errors,
    )
