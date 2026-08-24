"""HTTP security header and cookie-flag analysis."""

from __future__ import annotations

import http.cookies
import re

from .fetch import FetchResult
from .findings import Finding, Severity

_VERSION_PATTERN = re.compile(r"\d+\.\d+")


def _header(headers: dict[str, str], name: str) -> str | None:
    name_lower = name.lower()
    for key, value in headers.items():
        if key.lower() == name_lower:
            return value
    return None


def check_headers(result: FetchResult, scheme: str) -> list[Finding]:
    findings: list[Finding] = []
    headers = result.headers

    if scheme == "https" and _header(headers, "Strict-Transport-Security") is None:
        findings.append(
            Finding(
                id="missing-hsts",
                title="Missing Strict-Transport-Security header",
                severity=Severity.HIGH,
                owasp_category="A02:2021 Cryptographic Failures",
                description="The response over HTTPS did not set HSTS, so browsers "
                "will still accept a plaintext HTTP connection to this host, enabling "
                "SSL-stripping downgrade attacks.",
                remediation="Set 'Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains' (add 'preload' once verified).",
            )
        )

    csp = _header(headers, "Content-Security-Policy")
    if csp is None:
        findings.append(
            Finding(
                id="missing-csp",
                title="Missing Content-Security-Policy header",
                severity=Severity.MEDIUM,
                owasp_category="A05:2021 Security Misconfiguration",
                description="No CSP was set, so the browser applies no restriction on "
                "which scripts, styles, or frames the page may load — reducing "
                "defense-in-depth against XSS.",
                remediation="Define a Content-Security-Policy appropriate to the app, "
                "starting from a restrictive default-src and widening as needed.",
            )
        )
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        findings.append(
            Finding(
                id="weak-csp",
                title="Content-Security-Policy allows unsafe-inline/unsafe-eval",
                severity=Severity.LOW,
                owasp_category="A05:2021 Security Misconfiguration",
                description="The CSP is present but permits inline scripts or eval, "
                "which significantly weakens its protection against XSS.",
                evidence=csp,
                remediation="Move inline scripts to external files and use nonces or "
                "hashes instead of 'unsafe-inline'/'unsafe-eval'.",
            )
        )

    if _header(headers, "X-Content-Type-Options") is None:
        findings.append(
            Finding(
                id="missing-x-content-type-options",
                title="Missing X-Content-Type-Options header",
                severity=Severity.LOW,
                owasp_category="A05:2021 Security Misconfiguration",
                description="Without 'nosniff', some browsers will MIME-sniff "
                "responses, which can allow non-script content to be executed as "
                "script in certain upload/reflection scenarios.",
                remediation="Set 'X-Content-Type-Options: nosniff'.",
            )
        )

    has_frame_ancestors = csp is not None and "frame-ancestors" in csp
    if _header(headers, "X-Frame-Options") is None and not has_frame_ancestors:
        findings.append(
            Finding(
                id="missing-clickjacking-protection",
                title="Missing clickjacking protection",
                severity=Severity.MEDIUM,
                owasp_category="A05:2021 Security Misconfiguration",
                description="Neither X-Frame-Options nor a CSP frame-ancestors "
                "directive is set, so the page can be embedded in a hostile iframe "
                "for clickjacking attacks.",
                remediation="Set 'X-Frame-Options: DENY' (or SAMEORIGIN) or a CSP "
                "'frame-ancestors' directive.",
            )
        )

    if _header(headers, "Referrer-Policy") is None:
        findings.append(
            Finding(
                id="missing-referrer-policy",
                title="Missing Referrer-Policy header",
                severity=Severity.LOW,
                owasp_category="A05:2021 Security Misconfiguration",
                description="Without an explicit Referrer-Policy, the browser default "
                "may leak full URLs (including query strings/tokens) to third-party "
                "sites via outbound links.",
                remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' "
                "or stricter.",
            )
        )

    if _header(headers, "Permissions-Policy") is None:
        findings.append(
            Finding(
                id="missing-permissions-policy",
                title="Missing Permissions-Policy header",
                severity=Severity.INFO,
                owasp_category="A05:2021 Security Misconfiguration",
                description="No Permissions-Policy was set to restrict powerful "
                "browser features (camera, microphone, geolocation, etc.) for this "
                "origin and any embedded content.",
                remediation="Set a Permissions-Policy that disables features the app "
                "doesn't use.",
            )
        )

    for header_name in ("Server", "X-Powered-By"):
        value = _header(headers, header_name)
        if value and _VERSION_PATTERN.search(value):
            findings.append(
                Finding(
                    id=f"version-disclosure-{header_name.lower()}",
                    title=f"{header_name} header discloses software version",
                    severity=Severity.LOW,
                    owasp_category="A05:2021 Security Misconfiguration",
                    description=f"The {header_name} header advertises a specific "
                    "software version, making it easier for an attacker to look up "
                    "known vulnerabilities for that exact version.",
                    evidence=value,
                    remediation=f"Suppress or generalize the {header_name} header at "
                    "the web server / reverse proxy.",
                )
            )

    findings.extend(_check_cookies(result.set_cookie_headers, scheme))
    return findings


def _check_cookies(set_cookie_headers: list[str], scheme: str) -> list[Finding]:
    findings: list[Finding] = []
    for raw_cookie in set_cookie_headers:
        jar: http.cookies.SimpleCookie = http.cookies.SimpleCookie()
        try:
            jar.load(raw_cookie)
        except http.cookies.CookieError:
            continue

        for name, morsel in jar.items():
            missing = []
            if scheme == "https" and not morsel["secure"]:
                missing.append("Secure")
            if not morsel["httponly"]:
                missing.append("HttpOnly")
            if not morsel["samesite"]:
                missing.append("SameSite")

            if not missing:
                continue

            severity = Severity.HIGH if "Secure" in missing else Severity.MEDIUM
            findings.append(
                Finding(
                    id=f"cookie-missing-flags-{name}",
                    title=f"Cookie '{name}' missing {', '.join(missing)}",
                    severity=severity,
                    owasp_category="A05:2021 Security Misconfiguration",
                    description=f"The '{name}' cookie is set without: "
                    f"{', '.join(missing)}. Missing Secure allows transmission over "
                    "plaintext HTTP; missing HttpOnly allows JavaScript (and thus "
                    "XSS) to read it; missing SameSite weakens CSRF defenses.",
                    evidence=raw_cookie,
                    remediation="Reissue the cookie with Secure, HttpOnly, and an "
                    "explicit SameSite=Lax/Strict attribute.",
                )
            )
    return findings
