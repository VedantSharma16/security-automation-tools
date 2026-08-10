"""Security header and cookie-flag analysis.

Checks are based on the OWASP Secure Headers Project recommendations.
"""

from __future__ import annotations

from .findings import Finding, Severity

_MISSING_HEADER_CHECKS = [
    {
        "header": "Strict-Transport-Security",
        "id": "HDR-HSTS-MISSING",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "severity": Severity.MEDIUM,
        "description": "The response does not set Strict-Transport-Security, so browsers "
                        "may be tricked into connecting over plain HTTP (SSL-stripping).",
        "recommendation": "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
                           "on every HTTPS response.",
    },
    {
        "header": "Content-Security-Policy",
        "id": "HDR-CSP-MISSING",
        "title": "Missing Content-Security-Policy (CSP)",
        "severity": Severity.MEDIUM,
        "description": "No CSP header was found. CSP is a key mitigation against "
                        "cross-site scripting and data-injection attacks.",
        "recommendation": "Define a restrictive Content-Security-Policy, starting from "
                           "default-src 'self' and widening only as needed.",
    },
    {
        "header": "X-Content-Type-Options",
        "id": "HDR-NOSNIFF-MISSING",
        "title": "Missing X-Content-Type-Options",
        "severity": Severity.LOW,
        "description": "Without 'nosniff', some browsers may MIME-sniff responses away from "
                        "the declared Content-Type, enabling content-sniffing attacks.",
        "recommendation": "Send 'X-Content-Type-Options: nosniff' on all responses.",
    },
    {
        "header": "Referrer-Policy",
        "id": "HDR-REFERRER-MISSING",
        "title": "Missing Referrer-Policy",
        "severity": Severity.LOW,
        "description": "Without a Referrer-Policy, the full URL (including any sensitive "
                        "query parameters) may leak to third parties via the Referer header.",
        "recommendation": "Send 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    },
    {
        "header": "Permissions-Policy",
        "id": "HDR-PERMISSIONS-MISSING",
        "title": "Missing Permissions-Policy",
        "severity": Severity.INFO,
        "description": "No Permissions-Policy header was found to restrict access to "
                        "browser features (camera, microphone, geolocation, etc.).",
        "recommendation": "Send a Permissions-Policy header that denies features the "
                           "site does not use.",
    },
]

_INFO_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def _has_frame_protection(headers: dict, csp_value: str | None) -> bool:
    if "X-Frame-Options" in headers:
        return True
    if csp_value and "frame-ancestors" in csp_value.lower():
        return True
    return False


def analyze_security_headers(headers: dict) -> list[Finding]:
    """Return findings for missing/misconfigured security headers."""
    # Normalize to a case-insensitive lookup without depending on requests internals.
    lower_map = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []

    for check in _MISSING_HEADER_CHECKS:
        if check["header"].lower() not in lower_map:
            findings.append(Finding(
                id=check["id"],
                title=check["title"],
                severity=check["severity"],
                category="security-headers",
                description=check["description"],
                recommendation=check["recommendation"],
            ))

    csp_value = lower_map.get("content-security-policy")
    if not _has_frame_protection(headers, csp_value):
        findings.append(Finding(
            id="HDR-CLICKJACKING",
            title="No clickjacking protection (X-Frame-Options / frame-ancestors)",
            severity=Severity.MEDIUM,
            category="security-headers",
            description="The page can likely be embedded in a hostile <iframe>, enabling "
                        "clickjacking / UI-redress attacks.",
            recommendation="Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
        ))

    for header in _INFO_DISCLOSURE_HEADERS:
        if header.lower() in lower_map and lower_map[header.lower()].strip():
            findings.append(Finding(
                id=f"HDR-INFO-DISCLOSURE-{header.upper()}",
                title=f"Server software disclosed via {header}",
                severity=Severity.INFO,
                category="information-disclosure",
                description=f"The '{header}' header reveals server/framework details "
                            f"('{lower_map[header.lower()]}'), which helps attackers target "
                            f"known vulnerabilities.",
                recommendation=f"Suppress or genericize the '{header}' header at the "
                                f"reverse proxy / server configuration level.",
                evidence=lower_map[header.lower()],
            ))

    return findings


def analyze_cookies(set_cookie_headers: list[str]) -> list[Finding]:
    """Check Set-Cookie values for missing Secure / HttpOnly / SameSite attributes."""
    findings: list[Finding] = []
    for raw_cookie in set_cookie_headers:
        parts = [p.strip() for p in raw_cookie.split(";")]
        name = parts[0].split("=")[0] if parts else "unknown"
        flags_lower = [p.lower() for p in parts[1:]]

        if not any(f == "secure" for f in flags_lower):
            findings.append(Finding(
                id="COOKIE-NO-SECURE",
                title=f"Cookie '{name}' missing Secure flag",
                severity=Severity.MEDIUM,
                category="cookies",
                description="Without the Secure flag, this cookie can be transmitted over "
                            "unencrypted HTTP and intercepted on the network.",
                recommendation="Set the Secure attribute on all cookies served over HTTPS.",
                evidence=raw_cookie,
            ))
        if not any(f == "httponly" for f in flags_lower):
            findings.append(Finding(
                id="COOKIE-NO-HTTPONLY",
                title=f"Cookie '{name}' missing HttpOnly flag",
                severity=Severity.MEDIUM,
                category="cookies",
                description="Without HttpOnly, this cookie is readable by JavaScript, "
                            "increasing the impact of any XSS vulnerability.",
                recommendation="Set the HttpOnly attribute on session/auth cookies.",
                evidence=raw_cookie,
            ))
        if not any(f.startswith("samesite") for f in flags_lower):
            findings.append(Finding(
                id="COOKIE-NO-SAMESITE",
                title=f"Cookie '{name}' missing SameSite attribute",
                severity=Severity.LOW,
                category="cookies",
                description="Without SameSite, this cookie may be sent on cross-site "
                            "requests, weakening CSRF defenses.",
                recommendation="Set SameSite=Lax (or Strict) unless cross-site delivery "
                                "is explicitly required.",
                evidence=raw_cookie,
            ))
    return findings
