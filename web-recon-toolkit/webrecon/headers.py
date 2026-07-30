"""Analyze HTTP response headers for missing security controls and info disclosure.

Reference: OWASP Secure Headers Project
https://owasp.org/www-project-secure-headers/
"""

from __future__ import annotations

from typing import Mapping

from .models import Finding, Severity

# Headers whose mere presence (regardless of value) satisfies the control.
_PRESENCE_CHECKS = [
    {
        "header": "Strict-Transport-Security",
        "https_only": True,
        "severity": Severity.MEDIUM,
        "title": "Missing HSTS header",
        "description": (
            "The response does not set Strict-Transport-Security, so browsers "
            "will not be told to enforce HTTPS on subsequent visits, leaving "
            "users open to protocol-downgrade / SSL-stripping attacks."
        ),
        "remediation": (
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
            "on every HTTPS response."
        ),
        "owasp_ref": "OWASP ASVS 9.1 / A05:2021-Security Misconfiguration",
    },
    {
        "header": "Content-Security-Policy",
        "https_only": False,
        "severity": Severity.MEDIUM,
        "title": "Missing Content-Security-Policy header",
        "description": (
            "No CSP is set, so the browser applies no restriction on script, "
            "style, or frame sources, weakening the app's defense-in-depth "
            "against XSS and clickjacking."
        ),
        "remediation": (
            "Define a CSP restricting `default-src`, `script-src`, and "
            "`frame-ancestors` to trusted origins."
        ),
        "owasp_ref": "A05:2021-Security Misconfiguration",
    },
    {
        "header": "X-Content-Type-Options",
        "https_only": False,
        "severity": Severity.LOW,
        "title": "Missing X-Content-Type-Options header",
        "description": (
            "Without `nosniff`, some browsers will MIME-sniff response bodies, "
            "which can turn an upload/reflection endpoint into a stored-XSS "
            "vector."
        ),
        "remediation": "Send `X-Content-Type-Options: nosniff` on every response.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
    },
    {
        "header": "Referrer-Policy",
        "https_only": False,
        "severity": Severity.LOW,
        "title": "Missing Referrer-Policy header",
        "description": (
            "Without an explicit policy, full URLs (potentially including "
            "tokens or IDs in the path/query) may leak to third parties via "
            "the Referer header."
        ),
        "remediation": (
            "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter."
        ),
        "owasp_ref": "A01:2021-Broken Access Control",
    },
    {
        "header": "Permissions-Policy",
        "https_only": False,
        "severity": Severity.INFO,
        "title": "Missing Permissions-Policy header",
        "description": (
            "No Permissions-Policy is set, so the app does not opt out of "
            "browser features (camera, microphone, geolocation) it doesn't use."
        ),
        "remediation": "Send a `Permissions-Policy` header disabling unused features.",
        "owasp_ref": "A05:2021-Security Misconfiguration",
    },
]

# Headers whose presence itself is the problem (information disclosure).
_DISCLOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")

# Clickjacking is satisfied by EITHER X-Frame-Options OR a CSP frame-ancestors directive.
_CLICKJACKING_HEADER = "X-Frame-Options"


def _missing_frame_protection(headers: Mapping[str, str]) -> bool:
    if _CLICKJACKING_HEADER in headers:
        return False
    csp = headers.get("Content-Security-Policy", "")
    return "frame-ancestors" not in csp.lower()


def _check_cookies(set_cookie_headers: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    for cookie in set_cookie_headers:
        cookie = cookie.strip()
        if not cookie:
            continue
        name = cookie.split("=", 1)[0].strip()
        lowered = cookie.lower()
        missing = []
        if "secure" not in lowered:
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            findings.append(
                Finding(
                    id=f"cookie-flags-{name}",
                    title=f"Cookie '{name}' missing flag(s): {', '.join(missing)}",
                    severity=Severity.MEDIUM if "Secure" in missing or "HttpOnly" in missing else Severity.LOW,
                    category="cookies",
                    description=(
                        f"The '{name}' cookie is set without: {', '.join(missing)}. "
                        "Missing Secure/HttpOnly/SameSite flags increase exposure to "
                        "session theft via network interception, XSS, or CSRF."
                    ),
                    evidence=cookie,
                    remediation=(
                        "Set cookies with `Secure; HttpOnly; SameSite=Lax` (or `Strict`) "
                        "unless the cookie must be script-readable or cross-site by design."
                    ),
                    owasp_ref="A05:2021-Security Misconfiguration",
                )
            )
    return findings


def check_security_headers(
    headers: Mapping[str, str],
    is_https: bool,
    set_cookie_headers: list[str] | None = None,
) -> list[Finding]:
    """Inspect response headers and return one Finding per missing control or disclosure."""
    findings: list[Finding] = []

    for check in _PRESENCE_CHECKS:
        if check["https_only"] and not is_https:
            continue
        if check["header"] not in headers:
            findings.append(
                Finding(
                    id=f"header-missing-{check['header'].lower()}",
                    title=check["title"],
                    severity=check["severity"],
                    category="headers",
                    description=check["description"],
                    remediation=check["remediation"],
                    owasp_ref=check["owasp_ref"],
                )
            )

    if _missing_frame_protection(headers):
        findings.append(
            Finding(
                id="header-missing-frame-protection",
                title="Missing clickjacking protection",
                severity=Severity.MEDIUM,
                category="headers",
                description=(
                    "Neither X-Frame-Options nor a CSP frame-ancestors directive is "
                    "present, so the page can be embedded in a hostile iframe for "
                    "clickjacking or UI-redress attacks."
                ),
                remediation=(
                    "Send `X-Frame-Options: DENY` or a CSP with "
                    "`frame-ancestors 'none'`."
                ),
                owasp_ref="A05:2021-Security Misconfiguration",
            )
        )

    for header in _DISCLOSURE_HEADERS:
        value = headers.get(header)
        if value:
            findings.append(
                Finding(
                    id=f"disclosure-{header.lower()}",
                    title=f"Server software disclosed via {header}",
                    severity=Severity.LOW,
                    category="disclosure",
                    description=(
                        f"The `{header}` header reveals '{value}', helping an "
                        "attacker fingerprint the stack and target known CVEs."
                    ),
                    evidence=f"{header}: {value}",
                    remediation=f"Suppress or genericize the `{header}` header at the edge/proxy.",
                    owasp_ref="A05:2021-Security Misconfiguration",
                )
            )

    findings.extend(_check_cookies(set_cookie_headers or []))
    return findings
