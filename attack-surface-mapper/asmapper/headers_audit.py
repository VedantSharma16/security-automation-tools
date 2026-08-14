"""Security-header and cookie-flag audit for an already-fetched HTTP response."""

from __future__ import annotations

from .models import Finding, Severity

# header (lowercase) -> (severity, why it matters)
SECURITY_HEADERS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "No Content-Security-Policy: the browser has no server-imposed restriction on "
        "which scripts/styles/frames may execute, widening the blast radius of any XSS.",
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        "No HSTS header: browsers will still attempt plain HTTP first, leaving an opening "
        "for SSL-stripping / protocol-downgrade attacks on the first visit.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "No X-Content-Type-Options: nosniff, so browsers may MIME-sniff responses, which "
        "has historically enabled content-type confusion attacks.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "No X-Frame-Options and no frame-ancestors CSP directive: the page can be framed "
        "by a third-party site, enabling clickjacking.",
    ),
    "referrer-policy": (
        Severity.INFO,
        "No Referrer-Policy: full URLs (including any sensitive query parameters) may leak "
        "to third parties via the Referer header on outbound links.",
    ),
    "permissions-policy": (
        Severity.INFO,
        "No Permissions-Policy: default browser feature access (camera, geolocation, etc.) "
        "is left unrestricted for this origin.",
    ),
}


def audit_headers(headers: dict) -> list[Finding]:
    """Return one Finding per missing security header / weak cookie flag / version disclosure."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []

    csp = lower_headers.get("content-security-policy", "")
    for name, (severity, detail) in SECURITY_HEADERS.items():
        if name == "x-frame-options" and "frame-ancestors" in csp.lower():
            continue
        if name not in lower_headers:
            findings.append(
                Finding(
                    id=f"header-missing-{name}",
                    title=f"Missing security header: {name}",
                    severity=severity,
                    detail=detail,
                    category="headers",
                    recommendation=f"Add a {name} response header appropriate to the application.",
                )
            )

    server = lower_headers.get("server", "")
    powered_by = lower_headers.get("x-powered-by", "")
    for label, value in (("Server", server), ("X-Powered-By", powered_by)):
        if value and any(ch.isdigit() for ch in value):
            findings.append(
                Finding(
                    id=f"header-version-disclosure-{label.lower()}",
                    title=f"{label} header discloses version information",
                    severity=Severity.LOW,
                    detail=f"{label}: '{value}' — reveals software/version, narrowing exploit selection for an attacker.",
                    category="headers",
                    recommendation=f"Suppress or generalize the {label} header at the proxy/web-server config.",
                )
            )

    set_cookie = headers.get("Set-Cookie") or lower_headers.get("set-cookie")
    if set_cookie:
        cookie_lower = set_cookie.lower()
        if "secure" not in cookie_lower:
            findings.append(
                Finding(
                    id="cookie-missing-secure",
                    title="Cookie missing Secure flag",
                    severity=Severity.MEDIUM,
                    detail="A Set-Cookie response is missing the Secure flag, so the cookie can be sent over plaintext HTTP.",
                    category="headers",
                    recommendation="Add the Secure attribute to all session/auth cookies.",
                )
            )
        if "httponly" not in cookie_lower:
            findings.append(
                Finding(
                    id="cookie-missing-httponly",
                    title="Cookie missing HttpOnly flag",
                    severity=Severity.MEDIUM,
                    detail="A Set-Cookie response is missing the HttpOnly flag, so it is readable by JavaScript, raising XSS-to-session-theft impact.",
                    category="headers",
                    recommendation="Add the HttpOnly attribute to all session/auth cookies.",
                )
            )
        if "samesite" not in cookie_lower:
            findings.append(
                Finding(
                    id="cookie-missing-samesite",
                    title="Cookie missing SameSite attribute",
                    severity=Severity.LOW,
                    detail="A Set-Cookie response has no SameSite attribute, leaving the default (browser-dependent) cross-site request behavior in place.",
                    category="headers",
                    recommendation="Set SameSite=Lax or Strict on session/auth cookies unless cross-site delivery is required.",
                )
            )

    return findings
