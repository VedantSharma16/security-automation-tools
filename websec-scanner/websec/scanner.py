"""Orchestrates the individual checks into a single scan run."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests

from .checks import exposure, fingerprint, headers as headers_check, injection
from .checks import cookies as cookies_check
from .crawler import Crawler
from .models import Finding, Severity

DEFAULT_USER_AGENT = "websec-scanner/0.1 (+authorized-security-testing)"
DEFAULT_TIMEOUT = 8


@dataclass
class ScanResult:
    target: str
    started_at: float
    finished_at: float
    findings: list = field(default_factory=list)
    pages_crawled: int = 0
    endpoints_tested: int = 0
    active_checks_run: bool = False

    @property
    def highest_severity(self):
        if not self.findings:
            return None
        from .models import SEVERITY_RANK

        return max(self.findings, key=lambda f: SEVERITY_RANK[f.severity]).severity


class Scanner:
    def __init__(
        self,
        target: str,
        *,
        active: bool = False,
        max_pages: int = 25,
        timeout: int = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        session: requests.Session | None = None,
    ):
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Target must be an http(s) URL, got: {target!r}")
        self.target = target.rstrip("/") or target
        self.active = active
        self.max_pages = max_pages
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = user_agent

    def _fetch(self, url: str):
        """Returns (status_code, headers_dict, body_text). Never raises on
        request errors -- treated as a non-fatal miss for that URL."""
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return resp.status_code, resp.headers, resp.text
        except requests.RequestException:
            return None, {}, ""

    def _fetch_full(self, url: str):
        """Like `_fetch` but returns the full `requests.Response` (or None on
        error) so callers can reach raw headers -- needed for Set-Cookie,
        where duplicate headers must not be comma-merged."""
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def scan(self) -> ScanResult:
        started_at = time.monotonic()
        findings: list[Finding] = []

        resp = self._fetch_full(self.target)
        status = resp.status_code if resp is not None else None
        resp_headers = resp.headers if resp is not None else {}
        body = resp.text if resp is not None else ""
        if status is None:
            findings.append(
                Finding(
                    check="connectivity",
                    severity=Severity.INFO,
                    title="Target unreachable",
                    url=self.target,
                    detail="Could not connect to the target within the timeout.",
                )
            )
            return ScanResult(
                target=self.target,
                started_at=started_at,
                finished_at=time.monotonic(),
                findings=findings,
            )

        is_https = urlparse(self.target).scheme == "https"

        findings += headers_check.check_headers(self.target, resp_headers, is_https)
        findings += fingerprint.fingerprint(self.target, resp_headers, body)

        raw_set_cookie = self._get_raw_set_cookie_headers(resp)
        if raw_set_cookie:
            findings += cookies_check.check_cookies(self.target, raw_set_cookie, is_https)

        findings += self._run_exposure_probes()
        findings += self._check_robots()

        pages_crawled = 0
        endpoints_tested = 0
        if self.active:
            crawler = Crawler(self._fetch, max_pages=self.max_pages)
            visited, endpoints = crawler.crawl(self.target)
            pages_crawled = len(visited)
            active_findings, endpoints_tested = self._run_active_checks(endpoints)
            findings += active_findings

        return ScanResult(
            target=self.target,
            started_at=started_at,
            finished_at=time.monotonic(),
            findings=findings,
            pages_crawled=pages_crawled,
            endpoints_tested=endpoints_tested,
            active_checks_run=self.active,
        )

    def _get_raw_set_cookie_headers(self, resp) -> list[str]:
        # `requests` merges duplicate headers with ", " which corrupts
        # Set-Cookie (commas appear inside Expires=...); pull from the raw
        # urllib3 HTTPHeaderDict, which preserves duplicates, when available.
        if resp is None:
            return []
        raw_headers = getattr(getattr(resp, "raw", None), "headers", None)
        get_all = getattr(raw_headers, "get_all", None)
        if callable(get_all):
            return get_all("Set-Cookie") or []
        value = resp.headers.get("Set-Cookie")
        return [value] if value else []

    def _run_exposure_probes(self) -> list[Finding]:
        findings = []
        for probe in exposure.PROBES:
            url = urljoin(self.target + "/", probe.path)
            status, _, body = self._fetch(url)
            if status is None:
                continue
            finding = exposure.evaluate_probe_response(probe, status, body, url)
            if finding:
                findings.append(finding)
        return findings

    def _check_robots(self) -> list[Finding]:
        url = urljoin(self.target + "/", exposure.ROBOTS_PATH)
        status, _, body = self._fetch(url)
        if status != 200 or not body:
            return []
        paths = exposure.parse_robots_disclosures(body)
        if not paths:
            return []
        return [
            Finding(
                check="exposure",
                severity=Severity.INFO,
                title="robots.txt discloses non-public paths",
                url=url,
                detail="Disallowed paths (informational recon lead, not a "
                "vulnerability by itself): " + ", ".join(paths[:20]),
                evidence=", ".join(paths[:20]),
                recommendation="Ensure disallowed paths are also actually "
                "access-controlled, not just hidden from crawlers.",
            )
        ]

    def _run_active_checks(self, endpoints) -> tuple:
        findings: list[Finding] = []
        tested = 0
        for endpoint in endpoints:
            for param, kind, probe_url in injection.build_probes(endpoint):
                status, _, body = self._fetch(probe_url)
                if status is None:
                    continue
                tested += 1
                if kind == "xss":
                    finding = injection.check_reflected_xss(endpoint, param, status, body, probe_url)
                else:
                    finding = injection.check_sql_injection(endpoint, param, status, body, probe_url)
                if finding:
                    findings.append(finding)
        return findings, tested
