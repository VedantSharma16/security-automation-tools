"""Orchestrates the individual checkers into a single audit run."""

from __future__ import annotations

from urllib.parse import urlparse

from .cors import check_cors
from .disclosure import DEFAULT_SENSITIVE_PATHS, check_robots_txt, check_sensitive_paths, load_sensitive_paths
from .fetch import Fetcher, get_tls_info
from .findings import Finding, Severity
from .headers import check_headers
from .tls import check_tls


def run_audit(
    url: str,
    fetcher: Fetcher | None = None,
    tls_info_fn=get_tls_info,
    sensitive_paths_file=DEFAULT_SENSITIVE_PATHS,
    skip_tls: bool = False,
    skip_cors: bool = False,
    skip_disclosure: bool = False,
) -> list[Finding]:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")

    fetcher = fetcher or Fetcher()
    findings: list[Finding] = []

    base_result = fetcher.get(url)
    if not base_result.ok:
        return [
            Finding(
                id="target-unreachable",
                title="Target could not be reached",
                severity=Severity.INFO,
                owasp_category="N/A",
                description="The initial request to the target failed, so no "
                "further checks could run.",
                evidence=base_result.error or "unknown error",
                remediation="Verify the URL is correct and reachable from this "
                "machine.",
            )
        ]

    findings.extend(check_headers(base_result, parsed.scheme))

    if not skip_cors:
        findings.extend(check_cors(fetcher, url))

    if not skip_disclosure:
        path_specs = load_sensitive_paths(sensitive_paths_file)
        findings.extend(check_sensitive_paths(fetcher, url, path_specs))
        findings.extend(check_robots_txt(fetcher, url))

    if not skip_tls and parsed.scheme == "https":
        port = parsed.port or 443
        findings.extend(check_tls(parsed.hostname, port, tls_info_fn))

    return findings
