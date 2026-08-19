"""Orchestrate the recon pipeline: probe -> grade headers -> inspect TLS ->
fingerprint -> aggregate risk score. Two entry points share one aggregator:

- `scan()`      live network scan of a URL (real transport/cert_fetcher by default,
                injectable for tests).
- `analyze()`   offline analysis of a previously captured HTTP transaction
                (e.g. exported from a proxy), no network access at all.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from urllib.parse import urlparse

from .fingerprint import identify
from .http_probe import HttpResponse, Transport, default_transport, fetch
from .security_headers import grade_headers, letter_grade
from .tls_inspector import (
    OBSOLETE_PROTOCOLS,
    CertFetcher,
    TlsInfo,
    default_cert_fetcher,
    from_fixture,
    inspect as inspect_tls,
)

RISK_WEIGHTS = {"critical": 40, "high": 25, "medium": 10, "low": 3}


def _tls_findings(tls: TlsInfo) -> list[dict]:
    findings: list[dict] = []
    if tls.error:
        findings.append({
            "category": "tls", "severity": "medium",
            "message": f"TLS inspection failed: {tls.error}",
        })
        return findings

    if tls.days_until_expiry is not None:
        days = tls.days_until_expiry
        if days < 0:
            findings.append({
                "category": "tls", "severity": "critical",
                "message": f"TLS certificate expired {abs(days)} day(s) ago.",
            })
        elif days <= 14:
            findings.append({
                "category": "tls", "severity": "high",
                "message": f"TLS certificate expires in {days} day(s) -- renew immediately.",
            })
        elif days <= 30:
            findings.append({
                "category": "tls", "severity": "medium",
                "message": f"TLS certificate expires in {days} day(s).",
            })

    if tls.protocol_version in OBSOLETE_PROTOCOLS:
        findings.append({
            "category": "tls", "severity": "high",
            "message": f"Obsolete/weak TLS protocol negotiated: {tls.protocol_version}.",
        })

    return findings


def _risk_score(header_findings: list[dict], tls_findings: list[dict]) -> int:
    penalty = sum(RISK_WEIGHTS.get(f["severity"], 0) for f in header_findings + tls_findings)
    return max(0, 100 - penalty)


def build_result(url: str, http: HttpResponse, tls: TlsInfo | None) -> dict:
    """Aggregate a probe + optional TLS inspection into the final report dict."""
    if http.error:
        return {
            "target": url,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "http": {"status_code": http.status_code, "elapsed_ms": round(http.elapsed_ms, 1), "error": http.error},
            "security_headers": None,
            "tls": None,
            "tls_findings": [],
            "technologies": [],
            "risk_score": None,
            "risk_grade": None,
            "narrative": None,
        }

    is_https = urlparse(url).scheme == "https"
    header_report = grade_headers(http.headers, is_https)
    tech_matches = identify(http.headers, http.body)
    tls_findings = _tls_findings(tls) if tls else []
    risk_score = _risk_score(header_report["findings"], tls_findings)

    return {
        "target": url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "http": {"status_code": http.status_code, "elapsed_ms": round(http.elapsed_ms, 1), "error": None},
        "security_headers": header_report,
        "tls": asdict(tls) if tls else None,
        "tls_findings": tls_findings,
        "technologies": [vars(m) for m in tech_matches],
        "risk_score": risk_score,
        "risk_grade": letter_grade(risk_score),
        "narrative": None,
    }


def scan(
    url: str,
    timeout: float = 5.0,
    transport: Transport = default_transport,
    cert_fetcher: CertFetcher = default_cert_fetcher,
    skip_tls: bool = False,
) -> dict:
    """Live scan: fetch `url` and, for https targets, inspect its TLS certificate."""
    http = fetch(url, timeout=timeout, transport=transport)
    tls = None
    if http.error is None and urlparse(url).scheme == "https" and not skip_tls:
        tls = inspect_tls(url, timeout=timeout, cert_fetcher=cert_fetcher)
    return build_result(url, http, tls)


def analyze(fixture: dict) -> dict:
    """Offline re-analysis of a previously captured HTTP transaction. No network I/O."""
    url = fixture["url"]
    http = HttpResponse(
        url=url,
        status_code=fixture.get("status_code", 0),
        headers=fixture.get("headers", {}),
        body=fixture.get("body", ""),
        elapsed_ms=fixture.get("elapsed_ms", 0.0),
        error=fixture.get("error"),
    )
    tls = None
    if fixture.get("tls"):
        tls = from_fixture(urlparse(url).hostname or "", fixture["tls"])
    return build_result(url, http, tls)
