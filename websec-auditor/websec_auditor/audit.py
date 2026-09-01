"""Orchestrates a full audit: fetch -> header analysis -> TLS check -> fingerprint -> score."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import fetcher, headers as headers_mod
from .findings import Finding
from .fingerprint import fingerprint as fingerprint_fn
from .scoring import compute_grade
from .tls_check import TLSConnector, analyze_tls, fetch_tls_info

WELL_KNOWN_PATHS = ["robots.txt", ".well-known/security.txt"]


@dataclass
class AuditResult:
    url: str
    final_url: str
    status: int
    is_https: bool
    findings: list[Finding]
    technologies: list[str]
    score: int
    grade: str
    well_known: dict[str, int] = field(default_factory=dict)
    fetch_error: str | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "is_https": self.is_https,
            "score": self.score,
            "grade": self.grade,
            "technologies": self.technologies,
            "well_known": self.well_known,
            "fetch_error": self.fetch_error,
            "findings": [f.to_dict() for f in self.findings],
        }


def run_audit(
    url: str,
    *,
    timeout: float = fetcher.DEFAULT_TIMEOUT,
    opener=None,
    tls_connector: TLSConnector | None = None,
    check_well_known: bool = False,
    skip_tls: bool = False,
) -> AuditResult:
    normalized = fetcher.normalize_url(url)
    parsed = urlparse(normalized)
    is_https = parsed.scheme == "https"

    result = fetcher.fetch(normalized, timeout=timeout, opener=opener)

    findings: list[Finding] = []
    technologies: list[str] = []

    if not result.ok and result.error:
        return AuditResult(
            url=normalized,
            final_url=result.final_url,
            status=result.status,
            is_https=is_https,
            findings=[
                Finding(
                    id="fetch-failed",
                    severity="critical",
                    category="connectivity",
                    message=f"Could not reach {normalized}: {result.error}",
                    recommendation="Verify the host is reachable and the URL is correct.",
                )
            ],
            technologies=[],
            score=0,
            grade="F",
            fetch_error=result.error,
        )

    findings.extend(headers_mod.analyze_headers(result.headers, is_https=is_https))
    technologies = fingerprint_fn(
        result.headers, server_header=result.header("server"), body=result.body
    )

    if is_https and not skip_tls:
        tls_info = fetch_tls_info(parsed.hostname, parsed.port or 443, timeout=timeout, connector=tls_connector)
        findings.extend(analyze_tls(tls_info))

    well_known: dict[str, int] = {}
    if check_well_known:
        fetched = fetcher.fetch_well_known(normalized, WELL_KNOWN_PATHS, timeout=timeout, opener=opener)
        well_known = {path: r.status for path, r in fetched.items()}

    score, grade = compute_grade(findings)

    return AuditResult(
        url=normalized,
        final_url=result.final_url,
        status=result.status,
        is_https=is_https,
        findings=findings,
        technologies=technologies,
        score=score,
        grade=grade,
        well_known=well_known,
    )
