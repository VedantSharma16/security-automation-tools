"""HTTP response header security analysis.

Fetches the target over both HTTP and HTTPS and checks for the security
headers that matter most in practice: transport enforcement, content-type
sniffing protection, clickjacking protection, and content-injection
mitigation. Also flags plaintext HTTP that doesn't redirect to HTTPS, and
flags version-disclosing `Server`/`X-Powered-By` banners, which make
targeted exploit selection easier for an attacker.
"""

from __future__ import annotations

import requests

from .findings import Finding, Severity

_SECURITY_HEADERS = {
    "Strict-Transport-Security": Severity.HIGH,
    "Content-Security-Policy": Severity.MEDIUM,
    "X-Content-Type-Options": Severity.LOW,
    "X-Frame-Options": Severity.MEDIUM,
    "Referrer-Policy": Severity.LOW,
    "Permissions-Policy": Severity.LOW,
}
_BANNER_HEADERS = ("Server", "X-Powered-By")


def fetch(
    url: str, timeout: float = 10.0, session: requests.Session | None = None
) -> requests.Response | None:
    """Fetch `url`, returning the response or None if the host is unreachable."""
    session = session or requests.Session()
    try:
        return session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None


def analyze(domain: str, timeout: float = 10.0, session: requests.Session | None = None) -> dict:
    """Fetch both schemes for `domain` and return their reachability/headers."""
    session = session or requests.Session()
    https_response = fetch(f"https://{domain}", timeout=timeout, session=session)
    http_response = fetch(f"http://{domain}", timeout=timeout, session=session)

    return {
        "https": _describe(https_response),
        "http": _describe(http_response),
    }


def _describe(response: requests.Response | None) -> dict | None:
    if response is None:
        return None
    return {
        "status_code": response.status_code,
        "final_url": response.url,
        "headers": dict(response.headers),
    }


def build_findings(domain: str, result: dict) -> list[Finding]:
    findings: list[Finding] = []
    https_info = result.get("https")
    http_info = result.get("http")

    if https_info is None and http_info is None:
        findings.append(
            Finding(
                source="http_headers",
                severity=Severity.INFO,
                title="Host unreachable over HTTP(S)",
                detail=f"{domain} did not respond to an HTTP or HTTPS request.",
            )
        )
        return findings

    if https_info is None:
        findings.append(
            Finding(
                source="http_headers",
                severity=Severity.HIGH,
                title="HTTPS not available",
                detail=f"{domain} did not respond over HTTPS; only plaintext HTTP is reachable.",
            )
        )
    else:
        headers = https_info["headers"]
        for header, severity in _SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(
                    Finding(
                        source="http_headers",
                        severity=severity,
                        title=f"Missing {header} header",
                        detail=f"The HTTPS response from {domain} does not set {header}.",
                    )
                )
        for header in _BANNER_HEADERS:
            if header in headers:
                findings.append(
                    Finding(
                        source="http_headers",
                        severity=Severity.LOW,
                        title=f"{header} banner disclosed",
                        detail=f"{domain} discloses '{headers[header]}' via the {header} header.",
                    )
                )

    if http_info is not None and not http_info["final_url"].startswith("https://"):
        findings.append(
            Finding(
                source="http_headers",
                severity=Severity.MEDIUM,
                title="Plaintext HTTP does not redirect to HTTPS",
                detail=(
                    f"A request to http://{domain} was served over plaintext HTTP "
                    "instead of being redirected to HTTPS, exposing traffic to "
                    "downgrade and interception attacks."
                ),
            )
        )

    return findings
