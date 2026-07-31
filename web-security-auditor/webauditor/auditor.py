"""Top-level orchestration: fetch a URL, run header/TLS checks, and score it."""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional

from .fetcher import FetchResult, fetch
from .headers import evaluate_headers
from .models import Finding, Severity, Status
from .scoring import compute_score, grade_for_score
from .tls_inspector import TLSInfo, evaluate_tls
from .tls_inspector import inspect as inspect_tls


@dataclass
class AuditResult:
    url: str
    fetch_result: FetchResult
    tls_info: Optional[TLSInfo] = None
    findings: List[Finding] = field(default_factory=list)
    score: int = 0
    grade: str = "F"


def audit_url(url: str, timeout: float = 10.0, skip_tls: bool = False) -> AuditResult:
    """Run the full check suite (headers, cookies, TLS) against a single URL."""
    fetch_result = fetch(url, timeout=timeout)
    findings: List[Finding] = []

    if not fetch_result.ok:
        findings.append(Finding(
            "fetch-error", "HTTP Reachability", Status.FAIL, Severity.CRITICAL,
            f"Could not fetch {url}: {fetch_result.error}",
            "Confirm the host is reachable, DNS resolves, and the URL/port are correct.",
        ))
    else:
        findings.extend(evaluate_headers(fetch_result))

    tls_info: Optional[TLSInfo] = None
    parsed = urllib.parse.urlsplit(fetch_result.final_url or url)
    if not skip_tls and parsed.scheme.lower() == "https" and parsed.hostname:
        tls_info = inspect_tls(parsed.hostname, parsed.port or 443, timeout=timeout)
        findings.extend(evaluate_tls(tls_info))

    score = compute_score(findings)
    grade = grade_for_score(score)
    return AuditResult(
        url=url,
        fetch_result=fetch_result,
        tls_info=tls_info,
        findings=findings,
        score=score,
        grade=grade,
    )
