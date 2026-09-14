"""Orchestrates a full audit run: fetch -> checks -> score -> narrative."""

from __future__ import annotations

from collections.abc import Callable

from http_audit.cookies import check_cookies
from http_audit.cors import check_cors
from http_audit.exposure import check_exposure
from http_audit.fetcher import HttpResponse, live_fetch
from http_audit.headers import check_headers
from http_audit.llm_narrative import LLMNarrator
from http_audit.report import AuditReport
from http_audit.scoring import grade_for_score, score_findings
from http_audit.tls import check_tls

Transport = Callable[[str], HttpResponse]


def run_audit(
    url: str,
    transport: Transport | None = None,
    check_exposed: bool = False,
    narrator: LLMNarrator | None = None,
) -> AuditReport:
    """Run the full passive audit pipeline against ``url``.

    ``transport`` defaults to a real network fetch; tests inject a fake one.
    """
    fetch = transport or live_fetch
    response = fetch(url)

    findings = []
    findings.extend(check_headers(response))
    findings.extend(check_cookies(response))
    findings.extend(check_cors(response))
    findings.extend(check_tls(response))
    if check_exposed:
        findings.extend(check_exposure(url, fetch))

    score = score_findings(findings)
    grade = grade_for_score(score)

    report = AuditReport(
        url=url,
        status_code=response.status,
        findings=findings,
        score=score,
        grade=grade,
    )

    narrator = narrator or LLMNarrator()
    report.llm_backed = narrator.is_live
    report.summary = narrator.narrate(report)
    return report
