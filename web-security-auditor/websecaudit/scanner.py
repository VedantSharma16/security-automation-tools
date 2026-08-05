"""Orchestrates a fetch + all analysis modules into a single scan result.

Kept separate from ``fetcher.fetch`` so tests can call ``analyze()`` directly
against a hand-built ``FetchResult`` without any network access, and so the
CLI can inject a stub fetcher for its own tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .cookies import analyze_cookies
from .fetcher import FetchResult
from .findings import Finding, sort_by_severity
from .grading import compute_score, grade_for_score
from .headers import analyze_headers
from .tls import analyze_tls


@dataclass
class ScanResult:
    fetch: FetchResult
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A+"


def analyze(fetch_result: FetchResult) -> ScanResult:
    if not fetch_result.ok:
        error_finding = Finding(
            id="fetch-failed",
            severity="critical",
            category="transport",
            message=f"Could not reach {fetch_result.requested_url}: {fetch_result.error}",
            recommendation="Confirm the URL is reachable and re-run the scan.",
        )
        return ScanResult(fetch=fetch_result, findings=[error_finding], score=0, grade="F")

    findings: list[Finding] = []
    findings += analyze_headers(
        fetch_result.headers, fetch_result.scheme, fetch_result.redirect_chain
    )
    findings += analyze_cookies(fetch_result.set_cookie_headers, fetch_result.scheme)
    findings += analyze_tls(fetch_result.tls)
    findings = sort_by_severity(findings)

    score = compute_score(findings)
    grade = grade_for_score(score)
    return ScanResult(fetch=fetch_result, findings=findings, score=score, grade=grade)
