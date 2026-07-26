"""HTTP response security header analysis."""

from __future__ import annotations

from ..models import Finding, Severity

CHECK_NAME = "headers"

# header -> (severity if missing, recommendation)
_REQUIRED_HEADERS = {
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "Set a Content-Security-Policy to restrict script/style/frame sources "
        "and reduce XSS impact.",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Set 'X-Content-Type-Options: nosniff' to stop browsers from "
        "MIME-sniffing responses away from the declared Content-Type.",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Set a Referrer-Policy (e.g. 'strict-origin-when-cross-origin') to "
        "avoid leaking full URLs to third-party origins.",
    ),
    "Permissions-Policy": (
        Severity.INFO,
        "Set a Permissions-Policy to explicitly disable powerful browser "
        "features (camera, geolocation, etc.) the app doesn't use.",
    ),
}

# Either the header or an equivalent CSP directive is acceptable.
_FRAME_PROTECTION_HEADERS = ("X-Frame-Options",)


def _has_frame_protection(headers: dict, csp: str) -> bool:
    if any(h in headers for h in _FRAME_PROTECTION_HEADERS):
        return True
    return "frame-ancestors" in csp.lower()


def check_headers(url: str, headers: dict, is_https: bool) -> list[Finding]:
    """Inspect response headers for missing security controls.

    `headers` should be case-insensitive-friendly (e.g. a `requests`
    CaseInsensitiveDict or a plain dict already normalized by the caller).
    """
    findings: list[Finding] = []
    csp = headers.get("Content-Security-Policy", "")

    for header, (severity, recommendation) in _REQUIRED_HEADERS.items():
        if header not in headers:
            findings.append(
                Finding(
                    check=CHECK_NAME,
                    severity=severity,
                    title=f"Missing {header} header",
                    url=url,
                    detail=f"The response did not include a '{header}' header.",
                    recommendation=recommendation,
                )
            )

    if not _has_frame_protection(headers, csp):
        findings.append(
            Finding(
                check=CHECK_NAME,
                severity=Severity.MEDIUM,
                title="Missing clickjacking protection",
                url=url,
                detail="No 'X-Frame-Options' header and no CSP 'frame-ancestors' "
                "directive was present.",
                recommendation="Set 'X-Frame-Options: DENY' (or 'SAMEORIGIN') or "
                "a CSP 'frame-ancestors' directive.",
            )
        )

    if is_https and "Strict-Transport-Security" not in headers:
        findings.append(
            Finding(
                check=CHECK_NAME,
                severity=Severity.MEDIUM,
                title="Missing Strict-Transport-Security (HSTS) header",
                url=url,
                detail="The site is served over HTTPS but does not send an "
                "HSTS header.",
                recommendation="Set 'Strict-Transport-Security: max-age=63072000; "
                "includeSubDomains; preload' once all subdomains support HTTPS.",
            )
        )

    server = headers.get("Server", "")
    if server and any(c.isdigit() for c in server):
        findings.append(
            Finding(
                check=CHECK_NAME,
                severity=Severity.LOW,
                title="Server header discloses version information",
                url=url,
                detail=f"Server header: '{server}'",
                evidence=server,
                recommendation="Suppress or generalize the 'Server' header "
                "(e.g. via reverse proxy config) so it doesn't advertise exact "
                "software versions to attackers.",
            )
        )

    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        findings.append(
            Finding(
                check=CHECK_NAME,
                severity=Severity.LOW,
                title="X-Powered-By header discloses technology stack",
                url=url,
                detail=f"X-Powered-By: '{powered_by}'",
                evidence=powered_by,
                recommendation="Disable the 'X-Powered-By' header at the "
                "framework/server level.",
            )
        )

    return findings
